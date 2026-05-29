using System.Diagnostics;
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

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityAgent"/> class.
    /// </summary>
    /// <param name="scanners">System data scanners.</param>
    /// <param name="rules">Security check rules.</param>
    /// <param name="explanationProvider">Provider for human-readable explanations.</param>
    /// <param name="sentryAnalyzer">Optional SentryAnalyzer for log-based analysis.</param>
    /// <param name="profileProvider">Optional profile provider for SentryAnalyzer intensity profiles.</param>
    public SecurityAgent(
        IEnumerable<IScanner> scanners,
        IEnumerable<IRule> rules,
        IExplanationProvider explanationProvider,
        SentryAnalyzer? sentryAnalyzer = null,
        AnalysisProfileProvider? profileProvider = null)
    {
        _scanners = scanners?.ToList() ?? throw new ArgumentNullException(nameof(scanners));
        _rules = rules?.ToList() ?? throw new ArgumentNullException(nameof(rules));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _sentryAnalyzer = sentryAnalyzer;
        _profileProvider = profileProvider;
    }

    /// <inheritdoc />
    public async Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
    {
        var parser = new QueryParser();
        var intent = parser.Parse(query);

        if (intent == AgentIntent.Help)
        {
            return new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = GetHelpText(),
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        return await RunAuditAsync(intent, rawLog, ct);
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
            try
            {
                var result = rule.Evaluate(scanData);
                ruleResults.Add(result);
            }
            catch (Exception ex)
            {
                warnings.Add($"Rule {rule.Id} crashed: {ex.GetType().Name}");
            }
        }

        // Phase 3: Convert rule failures to Findings
        var agentFindings = new List<Finding>();
        foreach (var result in ruleResults.Where(r => !r.Passed))
        {
            var explanation = _explanationProvider.GetExplanation(result.ExplanationKey, result.Variables);
            agentFindings.Add(new Finding
            {
                Category = result.Category,
                Severity = result.Severity,
                SourceHost = "localhost",
                Target = result.Target,
                ShortDescription = result.Description,
                Details = explanation,
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow
            });
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
        var summary = BuildSummary(intent, agentFindings, logAnalysisResult, ruleResults);

        return new AgentResult
        {
            Intent = intent,
            AgentFindings = agentFindings,
            LogAnalysisResult = logAnalysisResult,
            Warnings = warnings,
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary
        };
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
            AgentIntent.FullAudit or AgentIntent.ExplainFinding => _rules,
            AgentIntent.FirewallCheck => _rules.Where(r => r.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.NetworkCheck => _rules.Where(r => r.Category.Equals("Network", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.ServiceCheck => _rules.Where(r => r.Category.Equals("Service", StringComparison.OrdinalIgnoreCase)),
            AgentIntent.PortCheck => _rules.Where(r => r.Category.Equals("Port", StringComparison.OrdinalIgnoreCase)),
            _ => Array.Empty<IRule>()
        };
    }

    private static string BuildSummary(AgentIntent intent, List<Finding> findings, AnalysisResult? logResult, List<RuleResult> allResults)
    {
        var passedCount = allResults.Count(r => r.Passed);
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
            AgentIntent.ExplainFinding => "Finding explanation audit",
            _ => "Audit"
        };

        var parts = new List<string> { $"{intentLabel} complete." };

        if (failedCount == 0)
        {
            parts.Add($"All {passedCount} checks passed.");
        }
        else
        {
            parts.Add($"{failedCount} issue(s) found, {highCritical} High/Critical.");
            if (passedCount > 0)
            {
                parts.Add($"{passedCount} check(s) passed.");
            }
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
        "You can also paste a firewall log and ask for analysis.";
}
