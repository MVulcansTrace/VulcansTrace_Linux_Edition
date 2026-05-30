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
    private readonly object _historyLock = new();
    private readonly List<(string RuleId, Finding Finding)> _lastFindings = new();

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
    public SecurityAgent(
        IEnumerable<IScanner> scanners,
        IEnumerable<IRule> rules,
        IExplanationProvider explanationProvider,
        SentryAnalyzer? sentryAnalyzer = null,
        AnalysisProfileProvider? profileProvider = null,
        ISuppressionStore? suppressionStore = null,
        MachineRole machineRole = MachineRole.Server,
        IRulePolicyProvider? policyProvider = null)
    {
        _scanners = scanners?.ToList() ?? throw new ArgumentNullException(nameof(scanners));
        _rules = rules?.ToList() ?? throw new ArgumentNullException(nameof(rules));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _sentryAnalyzer = sentryAnalyzer;
        _profileProvider = profileProvider;
        _suppressionStore = suppressionStore;
        _machineRole = machineRole;
        _policyProvider = policyProvider;
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

        return new AgentResult
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
            CrashedCount = crashedCount
        };
    }

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

        return new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = agentFindings,
            Warnings = warnings,
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary,
            RuleResults = new[] { result },
            PassedCount = result.Status == RuleStatus.Passed ? 1 : 0,
            FailedCount = result.Status == RuleStatus.Failed ? 1 : 0,
            CrashedCount = result.Status == RuleStatus.Crashed ? 1 : 0
        };
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

    private static string GetHelpText() =>
        "I can help you audit your Linux system security. Try asking:\n" +
        "• \"Is my system secure?\" or \"Run a full audit\"\n" +
        "• \"Check my firewall\" or \"How's my iptables?\"\n" +
        "• \"What ports are open?\"\n" +
        "• \"What services are running?\"\n" +
        "• \"Who am I talking to?\" (network connections)\n" +
        "You can also paste a firewall log and ask for analysis.\n" +
        "To explain a specific finding: \"explain FW-001\" or select a finding from the list.";
}
