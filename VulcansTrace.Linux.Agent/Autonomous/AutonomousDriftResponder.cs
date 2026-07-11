using System.Security.Cryptography;
using System.Text;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Autonomous;

/// <summary>
/// Orchestrates autonomous drift-response alerts for scheduled audits.
/// When a scheduled run detects baseline drift at or above a configured severity,
/// this responder re-runs the full analysis pipeline, composes a signed alert,
/// and pushes it through the configured notification channel.
/// </summary>
/// <remarks>
/// This is Stage 1 of autonomous drift response: alert enrichment and escalation only.
/// Remediation proposals may be attached to the alert, but execution always requires
/// explicit human approval.
/// </remarks>
public sealed class AutonomousDriftResponder
{
    private readonly IAgent _agent;
    private readonly IBaselineStore? _baselineStore;
    private readonly INotificationService _notificationService;
    private readonly Func<string, byte[]?> _signingKeyResolver;
    private readonly RemediationPlanBuilder _remediationPlanBuilder;
    private readonly SignedAlertVerifier _verifier;

    /// <summary>
    /// Initializes a new instance of the <see cref="AutonomousDriftResponder"/> class.
    /// </summary>
    /// <param name="agent">Agent used to run drift checks and full audits.</param>
    /// <param name="baselineStore">Baseline store. If null, drift response is disabled.</param>
    /// <param name="notificationService">Notification channel for the signed alert.</param>
    /// <param name="signingKeyResolver">Resolver that returns an HMAC signing key for a schedule id, or null when none is configured.</param>
    /// <param name="remediationPlanBuilder">Builder for remediation plan previews.</param>
    public AutonomousDriftResponder(
        IAgent agent,
        IBaselineStore? baselineStore,
        INotificationService notificationService,
        Func<string, byte[]?> signingKeyResolver,
        RemediationPlanBuilder remediationPlanBuilder)
        : this(agent, baselineStore, notificationService, signingKeyResolver, remediationPlanBuilder, new SignedAlertVerifier())
    {
    }

    /// <summary>
    /// Initializes a new instance with a supplied <see cref="SignedAlertVerifier"/>.
    /// </summary>
    internal AutonomousDriftResponder(
        IAgent agent,
        IBaselineStore? baselineStore,
        INotificationService notificationService,
        Func<string, byte[]?> signingKeyResolver,
        RemediationPlanBuilder remediationPlanBuilder,
        SignedAlertVerifier verifier)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _baselineStore = baselineStore;
        _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
        _signingKeyResolver = signingKeyResolver ?? throw new ArgumentNullException(nameof(signingKeyResolver));
        _remediationPlanBuilder = remediationPlanBuilder ?? throw new ArgumentNullException(nameof(remediationPlanBuilder));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    /// <summary>
    /// Evaluates drift for the schedule and, if severe enough, sends a signed autonomous alert.
    /// All failures are best-effort and logged; the schedule's audit result is never altered.
    /// </summary>
    /// <param name="schedule">The schedule that just ran.</param>
    /// <param name="statusLogger">Optional callback for status messages.</param>
    /// <param name="currentAudit">
    /// Optional already-completed full audit for this schedule's intent. When supplied, it is reused
    /// for alert enrichment instead of running a second audit, avoiding a redundant audit pass on
    /// each scheduled run. When null, a fresh audit is performed.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if an alert was sent; otherwise false.</returns>
    public async Task<bool> RespondToDriftAsync(
        AuditSchedule schedule,
        Action<string>? statusLogger = null,
        AgentResult? currentAudit = null,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (!schedule.AutonomousDriftResponse)
        {
            statusLogger?.Invoke("Autonomous drift response disabled for this schedule.");
            return false;
        }

        if (_baselineStore == null)
        {
            statusLogger?.Invoke("Autonomous drift response skipped: baseline storage unavailable.");
            return false;
        }

        try
        {
            statusLogger?.Invoke("Checking for baseline drift...");
            var driftResult = await _agent.CheckDriftAsync(schedule.Intent, rawLog: null, ct).ConfigureAwait(false);

            var driftFindings = driftResult.AgentFindings;
            var threshold = schedule.AutonomousDriftSeverityThreshold;
            var actionableFindings = driftFindings.Where(f => (int)f.Severity >= (int)threshold).ToList();

            if (actionableFindings.Count == 0)
            {
                var maxSeverity = driftFindings.Count > 0 ? driftFindings.Max(f => f.Severity) : (Severity?)null;
                statusLogger?.Invoke($"No drift at or above {threshold} threshold. Max drift severity: {maxSeverity?.ToString() ?? "none"}.");
                return false;
            }

            statusLogger?.Invoke($"Drift detected: {actionableFindings.Count} finding(s) at or above {threshold}. Composing alert...");
            AgentResult fullResult;
            if (currentAudit != null)
            {
                fullResult = currentAudit;
            }
            else
            {
                statusLogger?.Invoke("Running full analysis pipeline...");
                fullResult = await _agent.RunAuditAsync(schedule.Intent, rawLog: null, ct).ConfigureAwait(false);
            }

            var alert = ComposeAlert(schedule, threshold, actionableFindings, fullResult);
            var key = ResolveSigningKey(schedule.Id);
            if (key == null)
            {
                if (RequireSignedAlerts(schedule))
                {
                    statusLogger?.Invoke("Skipping drift alert: signed alerts are required (VT_REQUIRE_SIGNED_ALERTS or the schedule's require-signed setting) but no VT_ALERT_SIGNING_KEY is configured.");
                    return false;
                }
                statusLogger?.Invoke("Warning: no signing key configured (VT_ALERT_SIGNING_KEY). Alert will be sent UNSIGNED and cannot be authenticated.");
                alert = alert with { Signature = SignedAlertVerifier.UnsignedSentinel };
            }
            else
            {
                alert = alert with { Signature = _verifier.ComputeSignature(alert, key) };
            }

            await _notificationService.NotifySignedAlertAsync(alert, ct).ConfigureAwait(false);
            statusLogger?.Invoke($"Autonomous drift alert sent: {alert.Title}");
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Best-effort: drift response must never alter the schedule's audit outcome or fail its run.
            statusLogger?.Invoke($"Autonomous drift alert failed: {ErrorSanitizer.SanitizeException(ex)}");
            return false;
        }
    }

    private SignedAlertMessage ComposeAlert(
        AuditSchedule schedule,
        Severity threshold,
        IReadOnlyList<Finding> actionableFindings,
        AgentResult fullResult)
    {
        var maxSeverity = actionableFindings.Max(f => f.Severity);
        var ruleIds = actionableFindings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OfType<string>()
            .ToList();

        // Enrichment (attack chains, proactive alerts) is scoped to the drift findings so the
        // alert is internally consistent — every chain or regression cited pertains to a rule
        // that actually drifted, rather than to the full audit's broader posture.
        var driftRuleIdSet = ruleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var scopedChains = fullResult.AttackChains
            .Where(c => c.RuleIds.Any(r => driftRuleIdSet.Contains(r)))
            .ToList();
        var scopedProactive = fullResult.ProactiveAlerts
            .Where(a => driftRuleIdSet.Contains(a.RuleId))
            .ToList();

        var severityCounts = actionableFindings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var bodyBuilder = new StringBuilder();
        bodyBuilder.AppendLine($"Autonomous drift alert for schedule '{schedule.Name}': {actionableFindings.Count} new or worsened finding(s) at or above {threshold}.");
        bodyBuilder.AppendLine($"Max severity: {maxSeverity}.");
        bodyBuilder.AppendLine($"Severity breakdown: {FormatSeverityCounts(severityCounts)}.");

        if (scopedChains.Count > 0)
        {
            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine("Attack chains detected:");
            foreach (var chain in scopedChains.Take(3))
            {
                bodyBuilder.AppendLine($"  • {chain.Narrative}");
            }
        }

        if (scopedProactive.Count > 0)
        {
            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine("Drifted findings that returned after a verified fix:");
            foreach (var alert in scopedProactive.Take(5))
            {
                bodyBuilder.AppendLine($"  • {alert.RuleId}: {alert.Guidance}");
            }
        }

        if (!string.IsNullOrWhiteSpace(fullResult.Narrative?.FullText))
        {
            bodyBuilder.AppendLine();
            bodyBuilder.AppendLine("Current audit narrative:");
            bodyBuilder.AppendLine(fullResult.Narrative.FullText);
        }

        var attackChainNarratives = scopedChains
            .Select(c => c.Narrative)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToList();

        var proactiveAlertSummaries = scopedProactive
            .Select(a => $"{a.RuleId}: {a.Guidance}")
            .ToList();

        var remediationSummary = schedule.AllowAutoRemediate
            ? BuildRemediationSummary(schedule, actionableFindings)
            : null;

        return new SignedAlertMessage
        {
            Title = $"VulcansTrace drift alert: {maxSeverity} findings in '{schedule.Name}'",
            Body = bodyBuilder.ToString().Trim(),
            ScheduleId = schedule.Id,
            ScheduleName = schedule.Name,
            Nonce = GenerateNonce(),
            MaxSeverity = maxSeverity,
            DriftFindingCount = actionableFindings.Count,
            RuleIds = ruleIds,
            AttackChainNarratives = attackChainNarratives,
            ProactiveAlertSummaries = proactiveAlertSummaries,
            RemediationSummary = remediationSummary,
            TimestampUtc = fullResult.UtcTimestamp
        };
    }

    private static string GenerateNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    private string? BuildRemediationSummary(AuditSchedule schedule, IReadOnlyList<Finding> actionableFindings)
    {
        var filteredFindings = FilterFindingsByPrefix(schedule, actionableFindings);
        if (filteredFindings.Count == 0)
        {
            return "Remediation is enabled, but no drift findings match the configured rule-prefix scope.";
        }

        var plan = _remediationPlanBuilder.Build(filteredFindings);
        var policy = BuildPolicy(schedule);
        var validation = RemediationPlanValidator.Validate(plan);

        var totalApplyCommands = plan.Sections.Sum(s => s.ApplyCommands.Count);
        var permittedCommands = plan.Sections.Sum(s => s.ApplyCommands.Count(c => policy.IsPermitted(c.Safety)));
        var blockedCommands = totalApplyCommands - permittedCommands;
        var restartImpactCount = plan.Sections.Count(s => s.ImpactPreview?.HasRestartImpact == true);
        var lockoutRiskCount = plan.Sections.Count(s => s.ImpactPreview?.HasLockoutRisk == true);

        var summary = new StringBuilder();
        summary.AppendLine($"Remediation proposal ({filteredFindings.Count} of {actionableFindings.Count} findings in scope):");
        summary.AppendLine($"  Policy: {policy.Describe()}");
        summary.AppendLine($"  Total apply commands: {totalApplyCommands}");
        summary.AppendLine($"  Permitted by policy: {permittedCommands}");
        if (blockedCommands > 0)
        {
            summary.AppendLine($"  Blocked by policy: {blockedCommands}");
        }
        if (!validation.IsValid)
        {
            summary.AppendLine($"  Validation warnings: {validation.Errors.Count}");
        }
        if (restartImpactCount > 0)
        {
            summary.AppendLine($"  Sections with restart impact: {restartImpactCount}");
        }
        if (lockoutRiskCount > 0)
        {
            summary.AppendLine($"  Sections with lockout risk: {lockoutRiskCount}");
        }
        summary.AppendLine($"  Run 'vulcanstrace schedule remediate --id {schedule.Id} --dry-run' to preview.");

        return summary.ToString().Trim();
    }

    private static IReadOnlyList<Finding> FilterFindingsByPrefix(AuditSchedule schedule, IReadOnlyList<Finding> findings)
        => RemediationScopeFilter.Apply(findings, schedule.AllowedRemediationRulePrefixes);

    private static AutoFixPolicy BuildPolicy(AuditSchedule schedule) => new()
    {
        AllowReadOnly = true,
        AllowConfigChange = true,
        AllowServiceRestart = schedule.AllowRemediationRestart,
        AllowPackageInstall = schedule.AllowRemediationPackages,
        AllowDestructive = false,
        AllowUnknown = false,
        RequireValidation = true,
        RequireRollbackGuidance = true
    };

    private static string FormatSeverityCounts(Dictionary<Severity, int> counts)
    {
        var parts = new List<string>();
        foreach (Severity severity in Enum.GetValues<Severity>())
        {
            if (counts.TryGetValue(severity, out var count))
            {
                parts.Add($"{severity}={count}");
            }
        }
        return string.Join(", ", parts);
    }

    private byte[]? ResolveSigningKey(string scheduleId)
    {
        // The signing key is provided entirely by the host (VT_ALERT_SIGNING_KEY). When none is
        // configured we return null and the alert is sent UNSIGNED rather than signed with a
        // forgeable deterministic key — tamper-evidence must not be faked.
        return _signingKeyResolver(scheduleId);
    }

    private static bool RequireSignedAlerts(AuditSchedule schedule)
        => schedule.RequireSignedAlerts || IsTruthyEnvVar("VT_REQUIRE_SIGNED_ALERTS");

    private static bool IsTruthyEnvVar(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return value?.Equals("1", StringComparison.OrdinalIgnoreCase) == true
            || value?.Equals("true", StringComparison.OrdinalIgnoreCase) == true
            || value?.Equals("yes", StringComparison.OrdinalIgnoreCase) == true;
    }
}
