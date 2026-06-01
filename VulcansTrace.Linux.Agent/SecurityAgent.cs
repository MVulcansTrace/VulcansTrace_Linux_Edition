using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
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
    private readonly ISuppressionStore? _suppressionStore;
    private readonly IAuditHistoryStore? _historyStore;
    private readonly IBaselineStore? _baselineStore;

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
        IRiskScorecardBuilder? riskScorecardBuilder = null)
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
        _suppressionStore = suppressionStore;
        _historyStore = historyStore;
        _baselineStore = baselineStore;
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
            return await HandleExplainFindingAsync(agentQuery, ct);
        }

        if (IsFollowUpIntent(agentQuery.Intent))
        {
            return await HandleFollowUpAsync(agentQuery, ct);
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
        AgentIntent.SetBaseline => true,
        AgentIntent.CheckDrift => true,
        AgentIntent.ShowBaseline => true,
        AgentIntent.RiskScore => true,
        _ => false
    };

    private Task<AgentResult> HandleFollowUpAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        return agentQuery.Intent switch
        {
            AgentIntent.ShowChanges => HandleShowChangesAsync(ct),
            AgentIntent.ExplainCritical => HandleExplainCriticalAsync(ct),
            AgentIntent.FilterCategory => HandleFilterCategoryAsync(agentQuery, ct),
            AgentIntent.PrioritizeRemediation => HandlePrioritizeRemediationAsync(ct),
            AgentIntent.FixFinding => HandleFixFindingAsync(agentQuery, ct),
            AgentIntent.ListSuppressed => HandleListSuppressedAsync(ct),
            AgentIntent.SetBaseline => HandleSetBaselineAsync(agentQuery, ct),
            AgentIntent.CheckDrift => HandleCheckDriftAsync(agentQuery, ct),
            AgentIntent.ShowBaseline => HandleShowBaselineAsync(agentQuery, ct),
            AgentIntent.RiskScore => HandleRiskScoreAsync(ct),
            _ => Task.FromResult(new AgentResult
            {
                Intent = agentQuery.Intent,
                Summary = "I'm not sure how to answer that. Run an audit first, then try a follow-up question.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            })
        };
    }

    private Task<AgentResult> HandleShowChangesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No previous audit to compare against. Run an audit first, then ask what changed.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var allHistory = _historyStore?.GetAll();
        if (allHistory == null || allHistory.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No audit history available to compare against. Run at least two audits to see changes.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        // Skip the history entry that matches the current result (UI appends it after the audit).
        AuditHistoryEntry? previous = null;
        for (int i = 0; i < allHistory.Count; i++)
        {
            if (allHistory[i].TimestampUtc != _auditState.LastResult.UtcTimestamp)
            {
                previous = allHistory[i];
                break;
            }
        }

        if (previous == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowChanges,
                Summary = "No previous audit found to compare against. Run at least two audits to see changes.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var currentEntry = new AuditHistoryEntry
        {
            SnapshotId = Guid.NewGuid().ToString("N")[..8],
            TimestampUtc = _auditState.LastResult.UtcTimestamp,
            Intent = _auditState.LastResult.Intent,
            TotalFindings = _auditState.LastResult.AgentFindings.Count,
            SnapshotFindings = _auditState.LastResult.AgentFindings.Select(ToSnapshotFinding).ToList()
        };

        var diff = AuditDiffCalculator.Calculate(previous, currentEntry);

        var actionableFindings = new List<Finding>();
        foreach (var df in diff.NewFindings.Concat(diff.WorsenedFindings.Select(w => new DiffFinding
        {
            RuleId = w.RuleId,
            Target = w.Target,
            Severity = w.NewSeverity,
            ShortDescription = w.ShortDescription,
            Fingerprint = w.Fingerprint
        })))
        {
            actionableFindings.Add(new Finding
            {
                RuleId = df.RuleId,
                Category = "Change",
                Severity = ParseSeverityString(df.Severity),
                SourceHost = "localhost",
                Target = df.Target,
                ShortDescription = df.ShortDescription,
                Details = $"This finding is new or worsened since the last audit.",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow
            });
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ShowChanges,
            Summary = diff.Narrative,
            AgentFindings = actionableFindings,
            AuditDiff = diff,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleExplainCriticalAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainCritical,
                Summary = "Run an audit first, then ask me why findings are critical.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var criticalHigh = _auditState.LastResult.AgentFindings.Where(f => f.Severity >= Severity.High).ToList();

        if (criticalHigh.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainCritical,
                Summary = "No Critical or High findings in the last audit. Everything is at Medium or below.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var parts = new List<string> { $"**Critical / High Findings ({criticalHigh.Count})**", "" };
        foreach (var finding in criticalHigh)
        {
            var structured = _explanationProvider.ParseStructuredFromText(finding.Details);
            parts.Add($"**[{finding.RuleId}] {finding.ShortDescription}**");
            parts.Add(string.IsNullOrEmpty(structured.WhyItMatters) ? finding.Details : structured.WhyItMatters);
            parts.Add("");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ExplainCritical,
            Summary = string.Join("\n", parts),
            AgentFindings = criticalHigh,
            Warnings = Array.Empty<string>()
        });
    }

    private async Task<AgentResult> HandleFilterCategoryAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var category = agentQuery.TargetReference;

        if (_auditState.LastResult == null)
        {
            // Fallback: run a targeted audit for the inferred category
            var fallbackIntent = InferIntentFromCategory(category);
            if (fallbackIntent != AgentIntent.Help)
            {
                var savedLastResult = _auditState.LastResult;
                try
                {
                    var fallbackResult = await RunAuditAsync(fallbackIntent, null, ct);
                    return fallbackResult with { Intent = AgentIntent.FilterCategory };
                }
                finally
                {
                    _auditState.RememberResult(savedLastResult);
                }
            }

            return new AgentResult
            {
                Intent = AgentIntent.FilterCategory,
                Summary = "Run an audit first, then ask me to filter by category.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        if (string.IsNullOrWhiteSpace(category))
        {
            return new AgentResult
            {
                Intent = AgentIntent.FilterCategory,
                Summary = "Please specify a category to filter by (e.g., 'show only firewall issues').",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var filtered = _auditState.LastResult.AgentFindings
            .Where(f => f.Category.Contains(category, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var summary = filtered.Count > 0
            ? $"Showing {filtered.Count} {category} issue(s) from the last audit."
            : $"No {category} issues found in the last audit.";

        return new AgentResult
        {
            Intent = AgentIntent.FilterCategory,
            Summary = summary,
            AgentFindings = filtered,
            Warnings = Array.Empty<string>()
        };
    }

    private Task<AgentResult> HandlePrioritizeRemediationAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "Run an audit first, then ask me what to fix first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_auditState.LastResult.AgentFindings.Count == 0)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "No active findings to remediate. Great job!",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var builder = new RemediationPlanBuilder(_explanationProvider);
        var plan = builder.Build(_auditState.LastResult.AgentFindings);
        var sorted = plan.Sections.OrderByDescending(s => ParseSeverityFromSummary(s.FindingSummary)).ToList();
        var sortedPlan = plan with { Sections = sorted };

        var parts = new List<string> { "**Remediation Plan — Fix in this order**", "" };
        for (int i = 0; i < sorted.Count; i++)
        {
            var section = sorted[i];
            parts.Add($"{i + 1}. {section.FindingSummary}");
            if (!string.IsNullOrWhiteSpace(section.RiskNote))
            {
                parts.Add($"   Risk: {section.RiskNote}");
            }
            if (section.ApplyCommands.Count > 0)
            {
                parts.Add($"   Action: `{section.ApplyCommands[0].Command}`");
            }
            parts.Add("");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.PrioritizeRemediation,
            Summary = string.Join("\n", parts),
            AgentFindings = _auditState.LastResult.AgentFindings.OrderByDescending(f => f.Severity).ToList(),
            RemediationPlan = sortedPlan,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleFixFindingAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Run an audit first, then ask me to fix a specific finding (e.g., \"fix FW-001\").",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var reference = agentQuery.TargetReference;
        if (string.IsNullOrWhiteSpace(reference))
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = "Please specify which finding to fix (e.g., **fix FW-001**).",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var matched = _auditState.FindPreviousFinding(reference);
        if (matched == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I couldn't find finding **{reference}** in the last audit. Run an audit first or check the finding ID.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var builder = new RemediationPlanBuilder(_explanationProvider);
        var plan = builder.Build(new[] { matched });
        var section = plan.Sections.FirstOrDefault();

        if (section == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = $"I found **{reference}** but couldn't build a remediation plan for it.",
                AgentFindings = new[] { matched },
                Warnings = Array.Empty<string>()
            });
        }

        var validation = RemediationPlanValidator.Validate(plan);
        if (!validation.IsValid)
        {
            var parts = new List<string>
            {
                $"**Cannot guide remediation for {reference}**",
                "",
                "This finding has risky or unclassified commands that lack explicit rollback guidance. The plan was blocked for safety.",
                ""
            };
            foreach (var err in validation.Errors)
            {
                parts.Add($"  • {err}");
            }
            parts.Add("");
            parts.Add("Please review the explanation template and ensure rollback commands are provided.");

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FixFinding,
                Summary = string.Join("\n", parts),
                AgentFindings = new[] { matched },
                Warnings = validation.Errors.ToList(),
                RemediationPlan = plan
            });
        }

        var summaryParts = new List<string>
        {
            $"**Interactive Remediation: {section.RuleId}**",
            "",
            $"{section.FindingSummary}",
            ""
        };

        if (section.Preconditions.Count > 0)
        {
            summaryParts.Add("**Preconditions:**");
            foreach (var pre in section.Preconditions)
            {
                summaryParts.Add($"  • {pre}");
            }
            summaryParts.Add("");
        }

        if (section.BackupCommands.Count > 0)
        {
            summaryParts.Add($"**Backup ({section.BackupCommands.Count} command(s)):** Run these first to preserve state.");
            summaryParts.Add("");
        }

        summaryParts.Add($"**Apply ({section.ApplyCommands.Count} command(s)):** Step-by-step fix commands.");
        summaryParts.Add("");

        if (section.RollbackCommands.Count > 0 || section.RollbackHints.Count > 0)
        {
            summaryParts.Add($"**Rollback:** Available if something goes wrong.");
            summaryParts.Add("");
        }

        if (section.VerificationCommands.Count > 0)
        {
            summaryParts.Add($"**Verify ({section.VerificationCommands.Count} command(s)):** Confirm the fix worked.");
            summaryParts.Add("");
        }

        summaryParts.Add("Review each command before running it. Use the **Copy** button to grab commands.");

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.FixFinding,
            Summary = string.Join("\n", summaryParts),
            AgentFindings = new[] { matched },
            RemediationPlan = plan,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleListSuppressedAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListSuppressed,
                Summary = "Run an audit first, then ask me which findings are suppressed.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var suppressed = _auditState.LastResult.RuleResults.Where(r => r.Status == RuleStatus.Suppressed).ToList();

        if (suppressed.Count == 0)
        {
            var extra = _suppressionStore != null
                ? $" ({_suppressionStore.GetAll().Count} active suppression(s) in store, but none matched the last audit.)"
                : "";
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListSuppressed,
                Summary = $"No findings were suppressed in the last audit.{extra}",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var parts = new List<string> { $"**Suppressed Findings ({suppressed.Count})**", "" };
        foreach (var result in suppressed)
        {
            parts.Add($"• [{result.RuleId}] {result.Description} — Target: {result.Target}");
        }

        if (_suppressionStore != null)
        {
            parts.Add($"\nTotal active suppressions in store: {_suppressionStore.GetAll().Count}");
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ListSuppressed,
            Summary = string.Join("\n", parts),
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleSetBaselineAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Run an audit first, then say 'set baseline' to save it as a known-good snapshot.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_baselineStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Baseline storage is not available. Baselines cannot be saved.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var name = !string.IsNullOrWhiteSpace(agentQuery.TargetReference)
            ? agentQuery.TargetReference
            : $"{_auditState.LastAuditIntent}-{_auditState.LastResult.UtcTimestamp:yyyyMMdd-HHmmss}";

        var baselineId = Guid.NewGuid().ToString("N");
        var findings = _auditState.LastResult.AgentFindings;
        var snapshotFindings = findings.Select(ToSnapshotFinding).ToList();

        var entry = new BaselineEntry
        {
            BaselineId = baselineId,
            Name = name,
            CreatedUtc = _auditState.LastResult.UtcTimestamp,
            Intent = _auditState.LastAuditIntent,
            TotalFindings = findings.Count,
            CriticalCount = findings.Count(f => f.Severity == Severity.Critical),
            HighCount = findings.Count(f => f.Severity == Severity.High),
            MediumCount = findings.Count(f => f.Severity == Severity.Medium),
            LowCount = findings.Count(f => f.Severity == Severity.Low),
            InfoCount = findings.Count(f => f.Severity == Severity.Info),
            IsActive = true,
            SnapshotFindings = snapshotFindings,
            OriginalFindings = findings.ToList()
        };

        _baselineStore.Save(entry);
        _baselineStore.SetActive(baselineId);

        var warnings = new List<string>();
        if (!string.IsNullOrWhiteSpace(_baselineStore.PersistenceWarning))
        {
            warnings.Add(_baselineStore.PersistenceWarning);
        }

        var summary = $"Baseline '{name}' saved for {_auditState.LastAuditIntent} with {findings.Count} finding(s).";
        if (findings.Count > 0)
        {
            summary += $" ({entry.CriticalCount} Critical, {entry.HighCount} High).";
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.SetBaseline,
            Summary = summary,
            AgentFindings = Array.Empty<Finding>(),
            Warnings = warnings,
            Baseline = entry
        });
    }

    private async Task<AgentResult> HandleCheckDriftAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var intent = _auditState.LastResult?.Intent ?? AgentIntent.FullAudit;
        return await RunDriftCheckAsync(intent, null, ct);
    }

    private Task<AgentResult> HandleShowBaselineAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var intent = _auditState.LastResult?.Intent ?? AgentIntent.FullAudit;
        return ShowBaselineForIntentAsync(intent, ct);
    }

    private Task<AgentResult> ShowBaselineForIntentAsync(AgentIntent intent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_baselineStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "Baseline storage is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var baseline = _baselineStore.GetActive(intent);

        if (baseline == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = $"No baseline set for {intent}. Run an audit and say 'set baseline' to create one.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var findings = baseline.OriginalFindings.Count > 0
            ? baseline.OriginalFindings.Select(f => f with
            {
                Details = $"{f.Details}\n\n*(Part of baseline '{baseline.Name}' created {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC.)*"
            }).ToList()
            : baseline.SnapshotFindings.Select(sf => new Finding
            {
                RuleId = sf.RuleId,
                Category = string.IsNullOrEmpty(sf.Category) ? "Baseline" : sf.Category,
                Severity = ParseSeverityString(sf.Severity),
                SourceHost = "localhost",
                Target = sf.Target,
                ShortDescription = sf.ShortDescription,
                Details = $"Part of baseline '{baseline.Name}' created {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC.",
                TimeRangeStart = baseline.CreatedUtc,
                TimeRangeEnd = baseline.CreatedUtc
            }).ToList();

        var parts = new List<string>
        {
            $"**Baseline: {baseline.Name}**",
            $"Intent: {baseline.Intent}",
            $"Created: {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC",
            $"Findings: {baseline.TotalFindings} ({baseline.CriticalCount} Critical, {baseline.HighCount} High, {baseline.MediumCount} Medium, {baseline.LowCount} Low, {baseline.InfoCount} Info)"
        };

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ShowBaseline,
            Summary = string.Join("\n", parts),
            AgentFindings = findings,
            Warnings = Array.Empty<string>(),
            Baseline = baseline
        });
    }

    private Task<AgentResult> HandleRiskScoreAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.RiskScore,
                Summary = "Run an audit first, then ask for your risk score.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var risk = _auditState.LastResult.RiskScorecard;
        if (risk == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.RiskScore,
                Summary = "No risk scorecard available for the last audit.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var summary = $"**Risk Grade: {risk.LetterGrade}** ({risk.NumericScore:F1}) — {risk.SummaryStatus}\n" +
            $"Risk-relevant findings: {risk.TotalFindings}";

        if (risk.ByCategory.Count > 0)
        {
            summary += "\n\n**Top categories by deduction:**";
            foreach (var cat in risk.ByCategory.Take(5))
            {
                summary += $"\n• {cat.Category}: {cat.FindingCount} finding(s), avg severity {cat.AverageSeverity:F1}, deduction {cat.TotalDeduction:F1}";
            }
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.RiskScore,
            Summary = summary,
            AgentFindings = _auditState.LastResult.AgentFindings,
            Warnings = _auditState.LastResult.Warnings,
            RiskScorecard = risk
        });
    }

    /// <inheritdoc />
    public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return HandleSetBaselineAsync(new AgentQuery(AgentIntent.SetBaseline, name), ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return RunDriftCheckAsync(intent, rawLog, ct);
    }

    /// <inheritdoc />
    public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return ShowBaselineForIntentAsync(intent, ct);
    }

    private async Task<AgentResult> RunDriftCheckAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        if (_baselineStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "Baseline storage is not available. Drift detection cannot run.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var baseline = _baselineStore.GetActive(intent);
        if (baseline == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = $"No baseline set for {intent}. Run an audit and say 'set baseline' first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var savedLastResult = _auditState.LastResult;
        try
        {
            var liveResult = await RunAuditAsync(intent, rawLog, ct);

            var currentEntry = new AuditHistoryEntry
            {
                SnapshotId = Guid.NewGuid().ToString("N")[..8],
                TimestampUtc = liveResult.UtcTimestamp,
                Intent = liveResult.Intent,
                TotalFindings = liveResult.AgentFindings.Count,
                SnapshotFindings = liveResult.AgentFindings.Select(ToSnapshotFinding).ToList()
            };

            var baselineHistoryEntry = ToAuditHistoryEntry(baseline);
            var diff = AuditDiffCalculator.Calculate(baselineHistoryEntry, currentEntry);
            var baselineDiff = new BaselineDiffResult
            {
                Baseline = baseline,
                Diff = diff
            };

            var actionableFindings = new List<Finding>();
            foreach (var df in diff.NewFindings.Concat(diff.WorsenedFindings.Select(w => new DiffFinding
            {
                RuleId = w.RuleId,
                Target = w.Target,
                Severity = w.NewSeverity,
                ShortDescription = w.ShortDescription,
                Fingerprint = w.Fingerprint
            })))
            {
                actionableFindings.Add(new Finding
                {
                    RuleId = df.RuleId,
                    Category = "Drift",
                    Severity = ParseSeverityString(df.Severity),
                    SourceHost = "localhost",
                    Target = df.Target,
                    ShortDescription = df.ShortDescription,
                    Details = "This finding is new or worsened compared to the baseline.",
                    TimeRangeStart = DateTime.UtcNow,
                    TimeRangeEnd = DateTime.UtcNow
                });
            }

            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = baselineDiff.Narrative,
                AgentFindings = actionableFindings,
                BaselineDiff = baselineDiff,
                Warnings = liveResult.Warnings,
                PassedCount = liveResult.PassedCount,
                FailedCount = liveResult.FailedCount,
                SuppressedCount = liveResult.SuppressedCount,
                CrashedCount = liveResult.CrashedCount,
                RuleResults = liveResult.RuleResults,
                CapabilityReport = liveResult.CapabilityReport
            };
        }
        finally
        {
            _auditState.RememberResult(savedLastResult);
        }
    }

    private static AuditSnapshotFinding ToSnapshotFinding(Finding f) => new()
    {
        RuleId = f.RuleId ?? $"__null-{f.Fingerprint ?? f.Id.ToString("N")}",
        Target = f.Target,
        Severity = f.Severity.ToString(),
        ShortDescription = f.ShortDescription,
        Category = f.Category,
        Fingerprint = f.Fingerprint
    };

    private static AuditHistoryEntry ToAuditHistoryEntry(BaselineEntry baseline) => new()
    {
        SnapshotId = baseline.BaselineId,
        TimestampUtc = baseline.CreatedUtc,
        Intent = baseline.Intent,
        TotalFindings = baseline.TotalFindings,
        CriticalCount = baseline.CriticalCount,
        HighCount = baseline.HighCount,
        MediumCount = baseline.MediumCount,
        LowCount = baseline.LowCount,
        InfoCount = baseline.InfoCount,
        SnapshotFindings = baseline.SnapshotFindings
    };

    private static Severity ParseSeverityString(string severity) => severity.ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Info
    };

    private static Severity ParseSeverityFromSummary(string summary)
    {
        if (summary.Contains("Critical", StringComparison.OrdinalIgnoreCase)) return Severity.Critical;
        if (summary.Contains("High", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        if (summary.Contains("Medium", StringComparison.OrdinalIgnoreCase)) return Severity.Medium;
        if (summary.Contains("Low", StringComparison.OrdinalIgnoreCase)) return Severity.Low;
        return Severity.Info;
    }

    private static AgentIntent InferIntentFromCategory(string? category) => category?.ToLowerInvariant() switch
    {
        "firewall" or "iptables" or "nftables" => AgentIntent.FirewallCheck,
        "network" => AgentIntent.NetworkCheck,
        "service" or "daemon" => AgentIntent.ServiceCheck,
        "port" => AgentIntent.PortCheck,
        "ssh" or "sshd" => AgentIntent.SshCheck,
        "file" or "filepermission" or "permissions" => AgentIntent.FilePermissionCheck,
        "filesystem" or "suid" or "sgid" or "world-writable" or "sticky" or "unowned" => AgentIntent.FilesystemAuditCheck,
        "kernel" => AgentIntent.KernelCheck,
        "user" or "useraccount" or "account" or "password" or "shadow" or "uid" or "pam" => AgentIntent.UserAccountCheck,
        "logging" or "rsyslog" or "journald" or "audit" or "auditd" or "logrotate" or "forwarding" or "syslog" => AgentIntent.LoggingAuditCheck,
        "cron" or "crontab" or "scheduled" => AgentIntent.CronJobCheck,
        "packagevulnerability" or "package" or "cve" => AgentIntent.PackageVulnerabilityCheck,
        _ => AgentIntent.Help
    };

    /// <inheritdoc />
    public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var structured = _explanationProvider.ParseStructuredFromText(finding.Details);
        var summary = BuildStructuredSummary(finding, structured);

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new List<Finding> { finding },
            Warnings = Array.Empty<string>(),
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary
        });
    }

    private static string BuildStructuredSummary(Finding finding, Explanations.StructuredExplanation structured)
    {
        var parts = new List<string>
        {
            $"**[{finding.RuleId ?? "finding"}] {finding.ShortDescription}**",
            "",
            "**What was found**",
            string.IsNullOrEmpty(structured.WhatWasFound) ? finding.ShortDescription : structured.WhatWasFound,
            "",
            "**Why it matters**",
            string.IsNullOrEmpty(structured.WhyItMatters) ? "See details." : structured.WhyItMatters,
        };

        if (!string.IsNullOrEmpty(structured.HowToVerify))
        {
            parts.Add("");
            parts.Add("**How to verify**");
            parts.Add(structured.HowToVerify);
        }

        if (!string.IsNullOrEmpty(structured.SuggestedNextAction))
        {
            parts.Add("");
            parts.Add("**Suggested next action**");
            parts.Add(structured.SuggestedNextAction);
        }

        if (!string.IsNullOrEmpty(structured.Confidence))
        {
            parts.Add("");
            parts.Add($"**Confidence:** {structured.Confidence}");
        }

        if (!string.IsNullOrEmpty(structured.Caveats))
        {
            parts.Add($"**Caveats:** {structured.Caveats}");
        }

        return string.Join("\n", parts);
    }

    private async Task<AgentResult> HandleExplainFindingAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!string.IsNullOrWhiteSpace(agentQuery.TargetReference))
        {
            var reference = agentQuery.TargetReference;
            var matched = _auditState.FindPreviousFinding(reference);

            if (matched != null)
            {
                return await ExplainFindingAsync(matched, ct);
            }

            // Try to find a matching rule and run it specifically
            var matchingRule = _ruleEvaluationService.FindRuleById(reference);

            if (matchingRule != null)
            {
                return await RunSingleRuleAsync(matchingRule, ct);
            }

            return new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = $"I don't have a finding matching '{reference}'. Run an audit first, then ask me to explain a specific finding (e.g., 'explain FW-001').",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        return new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            Summary = "Please specify a finding to explain (e.g., 'explain FW-001') or select one from the findings list.",
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        };
    }

    private async Task<AgentResult> RunSingleRuleAsync(IRule rule, CancellationToken ct)
    {
        return await _singleRuleExplanationService.ExplainAsync(rule, ct);
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
