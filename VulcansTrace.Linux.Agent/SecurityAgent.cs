using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// Orchestrates the complete agent audit pipeline: scanning, rule evaluation,
/// optional log analysis, explanation generation, and result assembly.
/// </summary>
public sealed class SecurityAgent : IAgent
{
    private readonly ScannerCoordinator _scannerCoordinator;
    private readonly RuleEvaluationService _ruleEvaluationService;
    private readonly AgentResultComposer _resultComposer;
    private readonly FindingAssemblyService _findingAssemblyService;
    private readonly AgentLogAnalysisService _logAnalysisService;
    private readonly AgentAuditState _auditState;
    private readonly AgentResultFinalizer _resultFinalizer;
    private readonly SingleRuleExplanationService _singleRuleExplanationService;
    private readonly IExplanationProvider _explanationProvider;
    private readonly BaselineDriftService _baselineDriftService;
    private readonly FindingExplanationService _findingExplanationService;
    private readonly AgentFollowUpService _followUpService;
    private readonly GuidedRemediationService _guidedRemediationService;
    private readonly ISuppressionStore? _suppressionStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityAgent"/> class.
    /// </summary>
    /// <param name="scanners">System data scanners.</param>
    /// <param name="rules">Security check rules.</param>
    /// <param name="explanationProvider">Provider for human-readable explanations.</param>
    /// <param name="sentryAnalyzer">Optional SentryAnalyzer for log-based analysis.</param>
    /// <param name="profileProvider">Optional profile provider for SentryAnalyzer intensity profiles.</param>
    /// <param name="suppressionStore">Optional store for rule suppressions.</param>
    /// <param name="machineRole">The machine role used to tune rule strictness.</param>
    /// <param name="policyProvider">Optional provider for per-role rule policies.</param>
    /// <param name="historyStore">Optional store for audit history used by follow-up queries.</param>
    /// <param name="baselineStore">Optional store for configuration baselines.</param>
    /// <param name="scorecardBuilder">Optional builder for CIS compliance scorecards.</param>
    /// <param name="riskScorecardBuilder">Optional builder for risk scorecards.</param>
    /// <param name="sessionStore">Optional store for remediation sessions.</param>
    public SecurityAgent(
        IEnumerable<IScanner> scanners,
        IEnumerable<IRule> rules,
        IExplanationProvider explanationProvider,
        SentryAnalyzer? sentryAnalyzer = null,
        AnalysisProfileProvider? profileProvider = null,
        ISuppressionStore? suppressionStore = null,
        MachineRole machineRole = MachineRole.Server,
        IRulePolicyProvider? policyProvider = null,
        IAuditHistoryStore? historyStore = null,
        IBaselineStore? baselineStore = null,
        IComplianceScorecardBuilder? scorecardBuilder = null,
        IRiskScorecardBuilder? riskScorecardBuilder = null,
        ISessionStore? sessionStore = null)
    {
        _scannerCoordinator = new ScannerCoordinator(scanners);
        _ruleEvaluationService = new RuleEvaluationService(rules, machineRole, policyProvider);
        _resultComposer = new AgentResultComposer();
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _findingAssemblyService = new FindingAssemblyService(_explanationProvider, suppressionStore);
        _logAnalysisService = new AgentLogAnalysisService(sentryAnalyzer, profileProvider);
        _auditState = new AgentAuditState();
        _resultFinalizer = new AgentResultFinalizer(_auditState, historyStore, scorecardBuilder, riskScorecardBuilder);
        _singleRuleExplanationService = new SingleRuleExplanationService(
            _scannerCoordinator,
            _ruleEvaluationService,
            _findingAssemblyService,
            _resultComposer,
            _auditState,
            machineRole);
        _baselineDriftService = new BaselineDriftService(
            _auditState,
            baselineStore,
            RunAuditAsync);
        _findingExplanationService = new FindingExplanationService(
            _auditState,
            _ruleEvaluationService,
            _explanationProvider,
            _singleRuleExplanationService);
        _guidedRemediationService = new GuidedRemediationService(
            _auditState,
            new RemediationPlanBuilder(_explanationProvider),
            sessionStore,
            RunAuditAsync);
        _followUpService = new AgentFollowUpService(
            _auditState,
            _explanationProvider,
            historyStore,
            suppressionStore,
            _guidedRemediationService,
            RunAuditAsync);
        _suppressionStore = suppressionStore;
    }

    /// <inheritdoc />
    public async Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
    {
        var parser = new QueryParser();
        var agentQuery = parser.Parse(query);

        if (agentQuery.IsAmbiguous)
        {
            return new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = BuildClarificationPrompt(agentQuery),
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (agentQuery.Intent == AgentIntent.Help)
        {
            return new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = GetHelpText(),
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (agentQuery.Intent == AgentIntent.ExplainFinding)
        {
            return await _findingExplanationService.HandleExplainFindingAsync(agentQuery, ct);
        }

        if (IsBaselineIntent(agentQuery.Intent))
        {
            return agentQuery.Intent switch
            {
                AgentIntent.SetBaseline => await _baselineDriftService.SetBaselineAsync(agentQuery, ct),
                AgentIntent.CheckDrift => await _baselineDriftService.CheckDriftAsync(agentQuery, ct),
                AgentIntent.ShowBaseline => await _baselineDriftService.ShowBaselineAsync(agentQuery, ct),
                _ => await RunAuditAsync(agentQuery.Intent, rawLog, ct)
            };
        }

        if (agentQuery.Intent == AgentIntent.StartRemediation)
        {
            return await _guidedRemediationService.CreateSessionAsync(agentQuery.TargetReference ?? "", ct);
        }

        if (agentQuery.Intent == AgentIntent.VerifyRemediation)
        {
            return await _guidedRemediationService.RunVerificationAsync(agentQuery.TargetReference ?? "", ct);
        }

        if (IsFollowUpIntent(agentQuery.Intent))
        {
            return await _followUpService.HandleFollowUpAsync(agentQuery, ct);
        }

        return await RunAuditAsync(agentQuery.Intent, rawLog, ct);
    }

    private static string BuildClarificationPrompt(AgentQuery query)
    {
        var intents = new[] { query.Intent }
            .Concat(query.AlternativeIntents ?? Array.Empty<AgentIntent>())
            .Distinct()
            .Select(GetIntentDisplayName)
            .ToList();

        return intents.Count == 0
            ? "I could read that a couple of ways. Please ask for a specific audit area, such as firewall, ports, SSH, services, network, or full audit."
            : $"I could read that a couple of ways: {string.Join(", ", intents)}. Please ask for one specific audit area so I do not run the wrong check.";
    }

    private static string GetIntentDisplayName(AgentIntent intent) => intent switch
    {
        AgentIntent.FullAudit => "full audit",
        AgentIntent.FirewallCheck => "firewall",
        AgentIntent.NetworkCheck => "network",
        AgentIntent.ServiceCheck => "services",
        AgentIntent.PortCheck => "ports",
        AgentIntent.SshCheck => "SSH",
        AgentIntent.FilePermissionCheck => "file permissions",
        AgentIntent.FilesystemAuditCheck => "filesystem audit",
        AgentIntent.KernelCheck => "kernel hardening",
        AgentIntent.UserAccountCheck => "user accounts",
        AgentIntent.LoggingAuditCheck => "logging",
        AgentIntent.CronJobCheck => "cron jobs",
        AgentIntent.PackageVulnerabilityCheck => "package vulnerabilities",
        AgentIntent.ExplainFinding => "explain a finding",
        AgentIntent.ShowChanges => "audit changes",
        AgentIntent.ExplainCritical => "critical finding explanation",
        AgentIntent.FilterCategory => "filter findings",
        AgentIntent.PrioritizeRemediation => "remediation priority",
        AgentIntent.FixFinding => "guided remediation",
        AgentIntent.ListSuppressed => "suppressed findings",
        AgentIntent.SetBaseline => "set baseline",
        AgentIntent.CheckDrift => "baseline drift",
        AgentIntent.ShowBaseline => "show baseline",
        AgentIntent.RiskScore => "risk score",
        AgentIntent.StartRemediation => "start remediation",
        AgentIntent.VerifyRemediation => "verify remediation",
        AgentIntent.Help => "help",
        _ => intent.ToString()
    };

    /// <inheritdoc />
    public async Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Phase 1: Run all scanners in parallel
        var scannerResult = await _scannerCoordinator.RunAsync(ct);
        var scanData = scannerResult.ScanData;
        var warnings = scannerResult.Warnings.ToList();
        var capabilityReport = _resultComposer.BuildCapabilityReport(scanData.Capabilities);

        ct.ThrowIfCancellationRequested();

        // Phase 2: Evaluate rules against scan data
        var evaluatedRules = _ruleEvaluationService.EvaluateForIntent(intent, scanData, ct);
        var ruleResults = evaluatedRules.RuleResults.ToList();
        warnings.AddRange(evaluatedRules.Warnings);

        // Phase 3: Mark suppression status and convert rule failures to Findings
        var findingAssembly = _findingAssemblyService.Assemble(ruleResults);
        var agentFindings = findingAssembly.AgentFindings;
        var historyEntries = findingAssembly.HistoryEntries;
        ruleResults = findingAssembly.RuleResults.ToList();
        var suppressedCount = findingAssembly.SuppressedCount;
        warnings.AddRange(findingAssembly.Warnings);

        var passedCount = ruleResults.Count(r => r.Status == RuleStatus.Passed);
        var failedCount = ruleResults.Count(r => r.Status == RuleStatus.Failed);
        var crashedCount = ruleResults.Count(r => r.Status == RuleStatus.Crashed);

        // Phase 4: Optional log analysis
        var logAnalysis = await _logAnalysisService.AnalyzeAsync(rawLog, ct);
        var logAnalysisResult = logAnalysis.AnalysisResult;
        warnings.AddRange(logAnalysis.Warnings);

        // Phase 5: Build summary
        var summary = _resultComposer.BuildSummary(intent, agentFindings, logAnalysisResult, ruleResults, suppressedCount, crashedCount);

        return _resultFinalizer.FinalizeAudit(new AgentResultFinalizationRequest(
            intent,
            agentFindings,
            logAnalysisResult,
            warnings,
            summary,
            ruleResults,
            passedCount,
            failedCount,
            suppressedCount,
            crashedCount,
            capabilityReport,
            historyEntries));
    }

    private static bool IsFollowUpIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.ShowChanges => true,
        AgentIntent.ExplainCritical => true,
        AgentIntent.FilterCategory => true,
        AgentIntent.PrioritizeRemediation => true,
        AgentIntent.FixFinding => true,
        AgentIntent.ListSuppressed => true,
        AgentIntent.RiskScore => true,
        _ => false
    };

    private static bool IsBaselineIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.SetBaseline => true,
        AgentIntent.CheckDrift => true,
        AgentIntent.ShowBaseline => true,
        _ => false
    };

    /// <inheritdoc />
    public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _baselineDriftService.SetBaselineAsync(new AgentQuery(AgentIntent.SetBaseline, name), ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _baselineDriftService.RunDriftCheckAsync(intent, rawLog, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _baselineDriftService.ShowBaselineForIntentAsync(intent, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _findingExplanationService.ExplainFindingAsync(finding, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _guidedRemediationService.CreateSessionAsync(findingReference, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _guidedRemediationService.RunVerificationAsync(sessionId, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _guidedRemediationService.MarkSessionExportedAsync(sessionId, ct);
    }

    private static string GetHelpText() =>
        "I can help you audit your Linux system security. Try asking:\n" +
        "• \"Is my system secure?\" or \"Run a full audit\"\n" +
        "• \"Check my firewall\" or \"How's my iptables?\"\n" +
        "• \"What ports are open?\"\n" +
        "• \"What services are running?\"\n" +
        "• \"Who am I talking to?\" (network connections)\n" +
        "• \"Check my ssh\" or \"How's my SSH hardening?\"\n" +
        "• \"Check file permissions\" or \"Are my sensitive files secure?\"\n" +
        "• \"Check my filesystem\" or \"Any SUID binaries?\" or \"World-writable files?\"\n" +
        "• \"Check my user accounts\" or \"Are my passwords strong?\"\n" +
        "You can also paste a firewall log and ask for analysis.\n" +
        "To explain a specific finding: \"explain FW-001\" or select a finding from the list.\n" +
        "\nFollow-up questions (after an audit):\n" +
        "• \"What changed since the last audit?\"\n" +
        "• \"Why is this critical?\"\n" +
        "• \"Show only firewall issues\"\n" +
        "• \"What should I fix first?\"\n" +
        "• \"Fix FW-001\" — guided step-by-step remediation for a specific finding\n" +
        "• \"Which findings are suppressed?\"\n" +
        "• \"What's my risk grade?\" — show the overall risk scorecard\n" +
        "\nBaseline & drift detection:\n" +
        "• \"Set baseline\" — save the last audit as a known-good snapshot\n" +
        "• \"Check drift\" — compare live config against the saved baseline\n" +
        "• \"Show baseline\" — view the current baseline findings\n";}
