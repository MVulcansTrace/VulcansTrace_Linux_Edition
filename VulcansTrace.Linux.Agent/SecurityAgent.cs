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
    private readonly IReadOnlyList<IScanner> _scanners;
    private readonly IReadOnlyList<IRule> _rules;
    private readonly IExplanationProvider _explanationProvider;
    private readonly SentryAnalyzer? _sentryAnalyzer;
    private readonly AnalysisProfileProvider? _profileProvider;
    private readonly ISuppressionStore? _suppressionStore;
    private readonly MachineRole _machineRole;
    private readonly IRulePolicyProvider? _policyProvider;
    private readonly IAuditHistoryStore? _historyStore;
    private readonly IBaselineStore? _baselineStore;
    private readonly object _historyLock = new();
    private readonly List<(string RuleId, Finding Finding)> _lastFindings = new();
    private AgentResult? _lastResult;
    private AgentIntent _lastAuditIntent = AgentIntent.FullAudit;

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
        IBaselineStore? baselineStore = null)
    {
        _scanners = scanners?.ToList() ?? throw new ArgumentNullException(nameof(scanners));
        _rules = rules?.ToList() ?? throw new ArgumentNullException(nameof(rules));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _sentryAnalyzer = sentryAnalyzer;
        _profileProvider = profileProvider;
        _suppressionStore = suppressionStore;
        _machineRole = machineRole;
        _policyProvider = policyProvider;
        _historyStore = historyStore;
        _baselineStore = baselineStore;
    }

    /// <inheritdoc />
    public async Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
    {
        var parser = new QueryParser();
        var agentQuery = parser.Parse(query);

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

    /// <inheritdoc />
    public async Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var builder = new ScanDataBuilder();
        var warnings = new List<string>();

        // Phase 1: Run all scanners in parallel
        var scanTasks = _scanners.Select(s => RunScannerSafelyAsync(s, builder, ct)).ToArray();
        await Task.WhenAll(scanTasks);

        foreach (var task in scanTasks)
        {
            if (task.Result is { Length: > 0 } scannerWarnings)
            {
                warnings.AddRange(scannerWarnings);
            }
        }

        var scanData = builder.Build();
        warnings.AddRange(scanData.Warnings);
        var capabilityReport = BuildCapabilityReport(scanData.Capabilities);

        ct.ThrowIfCancellationRequested();

        // Phase 2: Evaluate rules against scan data
        var ruleResults = new List<RuleResult>();
        var rulesToRun = FilterRulesByIntent(intent);

        foreach (var rule in rulesToRun)
        {
            ct.ThrowIfCancellationRequested();
            var policy = _policyProvider?.GetPolicy(rule.Id, _machineRole);

            if (policy?.Enabled == false)
            {
                ruleResults.Add(CreatePolicyDisabledResult(rule));
                continue;
            }

            RuleResult result;
            try
            {
                if (rule is IContextualRule contextualRule)
                {
                    result = contextualRule.Evaluate(scanData, new RuleEvaluationContext(_machineRole, policy));
                }
                else
                {
                    result = rule.Evaluate(scanData);
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Rule {rule.Id} crashed: {ex.GetType().Name}");
                result = RuleResult.Crash(rule.Id, rule.Category, rule.Description);
            }

            if (!result.Passed && policy?.AutoPass == true)
            {
                result = result with { Passed = true, Status = RuleStatus.Passed };
            }

            if (policy?.SeverityOverride.HasValue == true && !result.Passed && result.Status != RuleStatus.Crashed)
            {
                result = result with { Severity = policy.SeverityOverride.Value };
            }

            ruleResults.Add(result);
        }

        // Phase 3: Mark suppression status and convert rule failures to Findings
        var agentFindings = new List<Finding>();
        var historyEntries = new List<(string RuleId, Finding Finding)>();
        var suppressedCount = 0;

        // Prune expired suppressions beyond the review retention window before checking.
        _suppressionStore?.PruneExpired();

        var processedResults = new List<RuleResult>(ruleResults.Count);
        foreach (var result in ruleResults)
        {
            if (result.Passed)
            {
                processedResults.Add(result);
                continue;
            }

            if (result.Status == RuleStatus.Crashed)
            {
                processedResults.Add(result);
                continue;
            }

            var explanation = _explanationProvider.GetExplanation(result.ExplanationKey, result.Variables);
            var finding = new Finding
            {
                Category = result.Category,
                Severity = result.Severity,
                SourceHost = "localhost",
                Target = result.Target,
                ShortDescription = result.Description,
                Details = explanation,
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                RuleId = result.RuleId
            };

            // Check suppression
            if (_suppressionStore != null && !string.IsNullOrEmpty(result.RuleId))
            {
                if (_suppressionStore.IsSuppressed(result.RuleId, result.Target, finding.Fingerprint))
                {
                    suppressedCount++;
                    processedResults.Add(result with { Status = RuleStatus.Suppressed });
                    continue;
                }
            }

            agentFindings.Add(finding);
            historyEntries.Add((result.RuleId, finding));
            processedResults.Add(result);
        }

        ruleResults = processedResults;
        var passedCount = ruleResults.Count(r => r.Status == RuleStatus.Passed);
        var failedCount = ruleResults.Count(r => r.Status == RuleStatus.Failed);
        var crashedCount = ruleResults.Count(r => r.Status == RuleStatus.Crashed);

        if (suppressedCount > 0)
        {
            warnings.Add($"{suppressedCount} finding(s) suppressed by user configuration.");
        }

        // Phase 4: Optional log analysis
        AnalysisResult? logAnalysisResult = null;
        if (!string.IsNullOrWhiteSpace(rawLog) && _sentryAnalyzer != null && _profileProvider != null)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                logAnalysisResult = await Task.Run(
                    () => _sentryAnalyzer.Analyze(rawLog, IntensityLevel.Medium, ct),
                    ct);
            }
            catch (Exception ex)
            {
                warnings.Add($"Log analysis failed: {ex.Message}");
            }
        }

        // Phase 5: Build summary
        var summary = BuildSummary(intent, agentFindings, logAnalysisResult, ruleResults, suppressedCount, crashedCount);

        ReplaceLastFindings(historyEntries);

        _lastResult = new AgentResult
        {
            Intent = intent,
            AgentFindings = agentFindings,
            LogAnalysisResult = logAnalysisResult,
            Warnings = warnings,
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary,
            RuleResults = ruleResults,
            PassedCount = passedCount,
            FailedCount = failedCount,
            SuppressedCount = suppressedCount,
            CrashedCount = crashedCount,
            CapabilityReport = capabilityReport
        };

        _lastAuditIntent = intent;
        return _lastResult;
    }

    private static bool IsFollowUpIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.ShowChanges => true,
        AgentIntent.ExplainCritical => true,
        AgentIntent.FilterCategory => true,
        AgentIntent.PrioritizeRemediation => true,
        AgentIntent.ListSuppressed => true,
        AgentIntent.SetBaseline => true,
        AgentIntent.CheckDrift => true,
        AgentIntent.ShowBaseline => true,
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
            AgentIntent.ListSuppressed => HandleListSuppressedAsync(ct),
            AgentIntent.SetBaseline => HandleSetBaselineAsync(agentQuery, ct),
            AgentIntent.CheckDrift => HandleCheckDriftAsync(agentQuery, ct),
            AgentIntent.ShowBaseline => HandleShowBaselineAsync(agentQuery, ct),
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

        if (_lastResult == null)
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
            if (allHistory[i].TimestampUtc != _lastResult.UtcTimestamp)
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
            TimestampUtc = _lastResult.UtcTimestamp,
            Intent = _lastResult.Intent,
            TotalFindings = _lastResult.AgentFindings.Count,
            SnapshotFindings = _lastResult.AgentFindings.Select(ToSnapshotFinding).ToList()
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

        if (_lastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainCritical,
                Summary = "Run an audit first, then ask me why findings are critical.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var criticalHigh = _lastResult.AgentFindings.Where(f => f.Severity >= Severity.High).ToList();

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

        if (_lastResult == null)
        {
            // Fallback: run a targeted audit for the inferred category
            var fallbackIntent = InferIntentFromCategory(category);
            if (fallbackIntent != AgentIntent.Help)
            {
                var savedLastResult = _lastResult;
                try
                {
                    var fallbackResult = await RunAuditAsync(fallbackIntent, null, ct);
                    return fallbackResult with { Intent = AgentIntent.FilterCategory };
                }
                finally
                {
                    _lastResult = savedLastResult;
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

        var filtered = _lastResult.AgentFindings
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

        if (_lastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.PrioritizeRemediation,
                Summary = "Run an audit first, then ask me what to fix first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_lastResult.AgentFindings.Count == 0)
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
        var plan = builder.Build(_lastResult.AgentFindings);
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
            AgentFindings = _lastResult.AgentFindings.OrderByDescending(f => f.Severity).ToList(),
            RemediationPlan = sortedPlan,
            Warnings = Array.Empty<string>()
        });
    }

    private Task<AgentResult> HandleListSuppressedAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_lastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListSuppressed,
                Summary = "Run an audit first, then ask me which findings are suppressed.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var suppressed = _lastResult.RuleResults.Where(r => r.Status == RuleStatus.Suppressed).ToList();

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

        if (_lastResult == null)
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
            : $"{_lastAuditIntent}-{_lastResult.UtcTimestamp:yyyyMMdd-HHmmss}";

        var baselineId = Guid.NewGuid().ToString("N");
        var findings = _lastResult.AgentFindings;
        var snapshotFindings = findings.Select(ToSnapshotFinding).ToList();

        var entry = new BaselineEntry
        {
            BaselineId = baselineId,
            Name = name,
            CreatedUtc = _lastResult.UtcTimestamp,
            Intent = _lastAuditIntent,
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

        var summary = $"Baseline '{name}' saved for {_lastAuditIntent} with {findings.Count} finding(s).";
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
        var intent = _lastResult?.Intent ?? AgentIntent.FullAudit;
        return await RunDriftCheckAsync(intent, null, ct);
    }

    private Task<AgentResult> HandleShowBaselineAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var intent = _lastResult?.Intent ?? AgentIntent.FullAudit;
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

        var savedLastResult = _lastResult;
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
            _lastResult = savedLastResult;
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
            var matched = FindPreviousFinding(reference);

            if (matched != null)
            {
                return await ExplainFindingAsync(matched, ct);
            }

            // Try to find a matching rule and run it specifically
            var matchingRule = _rules.FirstOrDefault(r =>
                r.Id.Equals(reference, StringComparison.OrdinalIgnoreCase));

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

    private Finding? FindPreviousFinding(string reference)
    {
        lock (_historyLock)
        {
            foreach (var entry in _lastFindings)
            {
                if (entry.RuleId.Equals(reference, StringComparison.OrdinalIgnoreCase))
                    return entry.Finding;
            }

            return _lastFindings
                .Select(entry => entry.Finding)
                .FirstOrDefault(finding => MatchesReference(finding, reference));
        }
    }

    private void ReplaceLastFindings(IEnumerable<(string RuleId, Finding Finding)> findings)
    {
        lock (_historyLock)
        {
            _lastFindings.Clear();
            _lastFindings.AddRange(findings);
        }
    }

    private static bool MatchesReference(Finding finding, string reference)
    {
        if (finding.ShortDescription.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Category.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Details.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Target.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private async Task<AgentResult> RunSingleRuleAsync(IRule rule, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var builder = new ScanDataBuilder();
        var warnings = new List<string>();

        var scanTasks = _scanners.Select(s => RunScannerSafelyAsync(s, builder, ct)).ToArray();
        await Task.WhenAll(scanTasks);

        foreach (var task in scanTasks)
        {
            if (task.Result is { Length: > 0 } scannerWarnings)
            {
                warnings.AddRange(scannerWarnings);
            }
        }

        var scanData = builder.Build();
        warnings.AddRange(scanData.Warnings);
        var capabilityReport = BuildCapabilityReport(scanData.Capabilities);

        var policy = _policyProvider?.GetPolicy(rule.Id, _machineRole);
        if (policy?.Enabled == false)
        {
            var disabledResult = CreatePolicyDisabledResult(rule);
            ReplaceLastFindings(Array.Empty<(string RuleId, Finding Finding)>());
            return new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                AgentFindings = Array.Empty<Finding>(),
                Warnings = warnings,
                UtcTimestamp = DateTime.UtcNow,
                Summary = $"Rule {rule.Id} is disabled by policy for {_machineRole}.",
                RuleResults = new[] { disabledResult },
                PassedCount = 1
            };
        }

        RuleResult result;
        try
        {
            if (rule is IContextualRule contextualRule)
            {
                result = contextualRule.Evaluate(scanData, new RuleEvaluationContext(_machineRole, policy));
            }
            else
            {
                result = rule.Evaluate(scanData);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Rule {rule.Id} crashed: {ex.GetType().Name}");
            result = RuleResult.Crash(rule.Id, rule.Category, rule.Description);
        }

        if (!result.Passed && policy?.AutoPass == true)
        {
            result = result with { Passed = true, Status = RuleStatus.Passed };
        }

        if (policy?.SeverityOverride.HasValue == true && !result.Passed && result.Status != RuleStatus.Crashed)
        {
            result = result with { Severity = policy.SeverityOverride.Value };
        }

        var agentFindings = new List<Finding>();
        if (!result.Passed && result.Status != RuleStatus.Crashed)
        {
            var explanation = _explanationProvider.GetExplanation(result.ExplanationKey, result.Variables);
            var finding = new Finding
            {
                Category = result.Category,
                Severity = result.Severity,
                SourceHost = "localhost",
                Target = result.Target,
                ShortDescription = result.Description,
                Details = explanation,
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                RuleId = result.RuleId
            };
            agentFindings.Add(finding);
            ReplaceLastFindings(new[] { (result.RuleId, finding) });
        }

        var summary = result.Status == RuleStatus.Crashed
            ? $"Rule {rule.Id} could not be evaluated."
            : agentFindings.Count > 0
                ? $"Explanation for [{agentFindings[0].Severity}] {agentFindings[0].ShortDescription}\n\n{agentFindings[0].Details}"
                : $"Rule {rule.Id} passed — no issue to explain.";

        _lastResult = new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = agentFindings,
            Warnings = warnings,
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary,
            RuleResults = new[] { result },
            PassedCount = result.Status == RuleStatus.Passed ? 1 : 0,
            FailedCount = result.Status == RuleStatus.Failed ? 1 : 0,
            CrashedCount = result.Status == RuleStatus.Crashed ? 1 : 0,
            CapabilityReport = capabilityReport
        };

        return _lastResult;
    }

    private static RuleResult CreatePolicyDisabledResult(IRule rule)
    {
        return RuleResult.Pass(rule.Id, rule.Category, rule.Id, $"{rule.Description} (disabled by policy)");
    }

    private static async Task<string[]> RunScannerSafelyAsync(IScanner scanner, ScanDataBuilder builder, CancellationToken ct)
    {
        try
        {
            await scanner.ScanAsync(builder, ct);
            return Array.Empty<string>();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new[] { $"Scanner '{scanner.Name}' failed: {ex.Message}" };
        }
    }

    private IEnumerable<IRule> FilterRulesByIntent(AgentIntent intent)
    {
        return intent switch
        {
            AgentIntent.FullAudit => _rules,
            AgentIntent.FirewallCheck => _rules.Where(r => r.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.NetworkCheck => _rules.Where(r => r.Category.Equals("Network", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ServiceCheck => _rules.Where(r => r.Category.Equals("Service", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.PortCheck => _rules.Where(r => r.Category.Equals("Port", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.SshCheck => _rules.Where(r => r.Category.Equals("SSH", StringComparison.OrdinalIgnoreCase)),
            _ => Array.Empty<IRule>()
        };
    }

    private static string BuildSummary(AgentIntent intent, List<Finding> findings, AnalysisResult? logResult, List<RuleResult> allResults, int suppressedCount = 0, int crashedCount = 0)
    {
        var passedCount = allResults.Count(r => r.Status == RuleStatus.Passed);
        var failedCount = findings.Count;
        var highCritical = findings.Count(f => f.Severity >= Severity.High);
        var logFindingsCount = logResult?.Findings.Count ?? 0;

        var intentLabel = intent switch
        {
            AgentIntent.FullAudit => "Full audit",
            AgentIntent.FirewallCheck => "Firewall check",
            AgentIntent.NetworkCheck => "Network check",
            AgentIntent.ServiceCheck => "Service check",
            AgentIntent.PortCheck => "Port check",
            AgentIntent.SshCheck => "SSH check",
            AgentIntent.ExplainFinding => "Finding explanation",
            _ => "Audit"
        };

        var parts = new List<string> { $"{intentLabel} complete." };

        if (failedCount == 0 && suppressedCount == 0 && crashedCount == 0)
        {
            parts.Add($"All {passedCount} checks passed.");
        }
        else if (failedCount == 0)
        {
            parts.Add(suppressedCount > 0
                ? $"0 active issue(s), {suppressedCount} suppressed."
                : "0 active issue(s).");
            if (passedCount > 0)
            {
                parts.Add($"{passedCount} check(s) passed.");
            }
        }
        else
        {
            parts.Add($"{failedCount} issue(s) found, {highCritical} High/Critical.");
            if (passedCount > 0)
            {
                parts.Add($"{passedCount} check(s) passed.");
            }
        }

        if (failedCount > 0 && suppressedCount > 0)
        {
            parts.Add($"{suppressedCount} suppressed.");
        }

        if (crashedCount > 0)
        {
            parts.Add($"{crashedCount} rule(s) crashed.");
        }

        if (logFindingsCount > 0)
        {
            parts.Add($"Log analysis found {logFindingsCount} additional finding(s).");
        }

        return string.Join(" ", parts);
    }

    private static string BuildCapabilityReport(IReadOnlyList<DataSourceCapability> capabilities)
    {
        if (capabilities.Count == 0)
            return string.Empty;

        var sourceOrder = new[]
        {
            "iptables",
            "nftables",
            "ss",
            "netstat",
            "ip addr",
            "ip route",
            "ss connections",
            "systemctl",
            "sshd -T",
            "sshd_config"
        };

        var orderedCapabilities = capabilities
            .Where(cap => !string.IsNullOrWhiteSpace(cap.SourceName))
            .GroupBy(cap => cap.SourceName, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(cap => GetCapabilityPriority(cap.Status)).First())
            .OrderBy(cap =>
            {
                var index = Array.FindIndex(sourceOrder, source => source.Equals(cap.SourceName, StringComparison.OrdinalIgnoreCase));
                return index >= 0 ? index : int.MaxValue;
            })
            .ThenBy(cap => cap.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (orderedCapabilities.Count == 0)
            return string.Empty;

        var parts = new List<string>(orderedCapabilities.Count);
        foreach (var cap in orderedCapabilities)
        {
            var statusLabel = cap.Status switch
            {
                CapabilityStatus.Available => "available",
                CapabilityStatus.Unavailable => "unavailable",
                CapabilityStatus.PermissionLimited => "permission-limited",
                _ => "unknown"
            };
            var detail = string.Empty;
            if (!string.IsNullOrWhiteSpace(cap.Detail) && cap.Status != CapabilityStatus.Available)
            {
                var sanitized = cap.Detail.Trim().Replace('\n', ' ').Replace('\r', ' ');
                if (sanitized.Length > 80)
                    sanitized = sanitized.Substring(0, 77) + "...";
                detail = $" ({sanitized})";
            }
            parts.Add($"{cap.SourceName} {statusLabel}{detail}");
        }

        return "Data sources: " + string.Join("; ", parts) + ".";
    }

    private static int GetCapabilityPriority(CapabilityStatus status) => status switch
    {
        CapabilityStatus.PermissionLimited => 3,
        CapabilityStatus.Available => 2,
        CapabilityStatus.Unavailable => 1,
        _ => 0
    };

    private static string GetHelpText() =>
        "I can help you audit your Linux system security. Try asking:\n" +
        "• \"Is my system secure?\" or \"Run a full audit\"\n" +
        "• \"Check my firewall\" or \"How's my iptables?\"\n" +
        "• \"What ports are open?\"\n" +
        "• \"What services are running?\"\n" +
        "• \"Who am I talking to?\" (network connections)\n" +
        "• \"Check my ssh\" or \"How's my SSH hardening?\"\n" +
        "You can also paste a firewall log and ask for analysis.\n" +
        "To explain a specific finding: \"explain FW-001\" or select a finding from the list.\n" +
        "\nFollow-up questions (after an audit):\n" +
        "• \"What changed since the last audit?\"\n" +
        "• \"Why is this critical?\"\n" +
        "• \"Show only firewall issues\"\n" +
        "• \"What should I fix first?\"\n" +
        "• \"Which findings are suppressed?\"\n" +
        "\nBaseline & drift detection:\n" +
        "• \"Set baseline\" — save the last audit as a known-good snapshot\n" +
        "• \"Check drift\" — compare live config against the saved baseline\n" +
        "• \"Show baseline\" — view the current baseline findings\n";}
