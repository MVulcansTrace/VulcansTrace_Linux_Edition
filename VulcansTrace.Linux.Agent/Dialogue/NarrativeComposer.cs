using System.Text;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Default implementation of <see cref="INarrativeComposer"/>.
/// Builds multi-paragraph narratives from findings, correlations, and memory.
/// Every paragraph cites its source ids.
/// </summary>
public sealed class NarrativeComposer : INarrativeComposer
{
    /// <inheritdoc />
    public Narrative Compose(
        AgentResult result,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory,
        EntityFrame entities)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(ruleHistory);
        ArgumentNullException.ThrowIfNull(entities);

        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var summary = ComposeSummary(result, sources);
        var keyFindings = ComposeKeyFindings(result, sources);
        var correlations = ComposeCorrelations(result, sources);
        var memory = ComposeMemory(result, ruleHistory, result.UtcTimestamp, sources);
        var nextSteps = ComposeNextSteps(result, sources);

        return new Narrative
        {
            Summary = summary,
            KeyFindingsParagraph = keyFindings,
            CorrelationsParagraph = correlations,
            MemoryParagraph = memory,
            NextStepsParagraph = nextSteps,
            SourceIds = sources.ToList()
        };
    }

    private static string ComposeSummary(AgentResult result, HashSet<string> sources)
    {
        if (result.AgentFindings.Count == 0)
        {
            return "No active findings. Your system looks clean for the checked scope.";
        }

        var critical = result.AgentFindings.Count(f => f.Severity == Severity.Critical);
        var high = result.AgentFindings.Count(f => f.Severity == Severity.High);
        var medium = result.AgentFindings.Count(f => f.Severity == Severity.Medium);
        var low = result.AgentFindings.Count(f => f.Severity == Severity.Low);
        var info = result.AgentFindings.Count(f => f.Severity == Severity.Info);

        var sb = new StringBuilder();
        sb.Append($"I found {result.AgentFindings.Count} finding(s)");

        var severityParts = new List<string>();
        if (critical > 0) severityParts.Add($"{critical} Critical");
        if (high > 0) severityParts.Add($"{high} High");
        if (medium > 0) severityParts.Add($"{medium} Medium");
        if (low > 0) severityParts.Add($"{low} Low");
        if (info > 0) severityParts.Add($"{info} Info");

        if (severityParts.Count > 0)
        {
            sb.Append($": {string.Join(", ", severityParts)}.");
        }
        else
        {
            sb.Append('.');
        }

        return sb.ToString();
    }

    private static string ComposeKeyFindings(AgentResult result, HashSet<string> sources)
    {
        if (result.AgentFindings.Count == 0)
            return string.Empty;

        var findings = result.AgentFindings
            .Where(f => !string.IsNullOrWhiteSpace(f.RuleId))
            .OrderByDescending(f => f.Severity)
            .Take(5)
            .ToList();

        if (findings.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Key findings:**");

        foreach (var finding in findings)
        {
            var ruleId = finding.RuleId!;
            sources.Add(ruleId);
            sb.AppendLine($"• **[{ruleId}]** {finding.ShortDescription} — {finding.Severity} severity.");
        }

        return sb.ToString().Trim();
    }

    private static string ComposeCorrelations(AgentResult result, HashSet<string> sources)
    {
        if (result.PostureCorrelations.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Combined risk:**");

        foreach (var correlation in result.PostureCorrelations.Take(3))
        {
            sources.Add(correlation.PatternId);
            sources.Add(correlation.RuleIdA);
            sources.Add(correlation.RuleIdB);
            // Always cite the rule IDs in the rendered text so the traceability invariant holds
            // even if the pattern template omits them.
            sb.AppendLine($"• **[{correlation.RuleIdA} + {correlation.RuleIdB}]** {correlation.Narrative}");
        }

        return sb.ToString().Trim();
    }

    private static string ComposeMemory(
        AgentResult result,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory,
        DateTime referenceUtc,
        HashSet<string> sources)
    {
        var relevantHistory = result.AgentFindings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(r => ruleHistory.TryGetValue(r!, out var entry) ? entry : null)
            .Where(e => e != null && e.SeverityHistory.Count >= 2)
            .Take(3)
            .ToList();

        if (relevantHistory.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Continuity:**");

        foreach (var entry in relevantHistory!)
        {
            sources.Add(entry!.RuleId);
            var days = (referenceUtc - entry.FirstSeenUtc).TotalDays;
            var daysText = days switch
            {
                <= 0 => "today",
                < 1 => "today",
                < 2 => "yesterday",
                < 7 => $"{(int)Math.Round(days)} days ago",
                < 30 => $"{(int)Math.Round(days / 7)} weeks ago",
                < 365 => $"{(int)Math.Round(days / 30)} months ago",
                _ => $"{(int)Math.Round(days / 365)} years ago"
            };

            var trendText = entry.Trend switch
            {
                RuleStatusTrend.Stable => "is still open",
                RuleStatusTrend.Worsening => "has worsened",
                RuleStatusTrend.Improving => "is improving",
                _ => "is still open"
            };

            sb.AppendLine($"• **{entry.RuleId}** was first seen {daysText} and {trendText}.");
        }

        return sb.ToString().Trim();
    }

    private static string ComposeNextSteps(AgentResult result, HashSet<string> sources)
    {
        var sb = new StringBuilder();

        if (result.AgentFindings.Any(f => f.Severity >= Severity.High))
        {
            sb.Append("Start with the highest-severity finding. ");
        }

        if (result.PostureCorrelations.Count > 0)
        {
            sb.Append("Address correlated findings together when possible. ");
        }

        sb.Append("Ask me to explain any finding, build a remediation plan, or fix a specific rule ID.");

        // Sources: not tied to a specific finding, so no source id added here.
        return sb.ToString().Trim();
    }
}
