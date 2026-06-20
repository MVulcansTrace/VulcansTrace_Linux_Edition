using System.Text;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Appends deterministic, history-aware depth sections to a single-rule explanation.
/// No reasoning or guessing: depth is selected from <see cref="ExplanationDepthResolver"/>
/// and the rendered text is built from immutable memory fields.
/// </summary>
internal static class AdaptiveExplanationBuilder
{
    /// <summary>
    /// Appends adaptive history/root-cause/escalation sections to the supplied string builder.
    /// </summary>
    /// <param name="sb">The builder for the explanation summary.</param>
    /// <param name="finding">The finding being explained.</param>
    /// <param name="entry">The rule's memory entry, or null if no history exists.</param>
    /// <param name="referenceUtc">The timestamp used for relative-time phrasing.</param>
    public static void AppendAdaptiveSections(
        StringBuilder sb,
        Finding finding,
        RuleMemoryEntry? entry,
        DateTime referenceUtc)
    {
        if (string.IsNullOrWhiteSpace(finding.RuleId))
            return;

        var depth = ExplanationDepthResolver.Resolve(entry);
        switch (depth)
        {
            case ExplanationDepth.Standard:
                return;

            case ExplanationDepth.Familiar:
                AppendHistory(sb, finding, entry!, referenceUtc, includeCycles: false);
                break;

            case ExplanationDepth.Recurring:
                AppendHistory(sb, finding, entry!, referenceUtc, includeCycles: true);
                AppendRootCause(sb, finding.RuleId);
                break;

            case ExplanationDepth.Escalating:
                AppendHistory(sb, finding, entry!, referenceUtc, includeCycles: true);
                AppendWhatChanged(sb, finding.RuleId!, entry!, referenceUtc);
                if (entry!.RemediationCycles.Count(c => c.IsClosed) >=
                    ExplanationDepthResolver.MinClosedCyclesForRecurring)
                {
                    AppendRootCause(sb, finding.RuleId);
                }
                break;
        }
    }

    private static void AppendHistory(
        StringBuilder sb,
        Finding finding,
        RuleMemoryEntry entry,
        DateTime referenceUtc,
        bool includeCycles)
    {
        sb.AppendLine();
        sb.AppendLine("**History**");

        var ruleId = finding.RuleId!;
        var observationCount = entry.SeverityHistory.Count;
        var firstSeenText = FormatRelativeTime(referenceUtc, entry.FirstSeenUtc);
        var trendText = FormatTrend(entry.Trend);

        sb.Append($"**[{ruleId}]** has {observationCount} retained audit snapshot(s), was first seen {firstSeenText}, and {trendText}.");

        if (includeCycles)
        {
            var closedCycles = entry.RemediationCycles.Count(c => c.IsClosed);
            if (closedCycles > 0)
            {
                sb.Append($" It has completed {closedCycles} remediation cycle(s).");
            }

            // Verified-fixed is independent of closed-cycle count: a rule can be fixed
            // but not yet have returned, so it has zero closed cycles yet still warrants
            // surfacing when it was last verified fixed.
            if (entry.LastVerifiedFixedUtc.HasValue)
            {
                var verifiedText = FormatRelativeTime(referenceUtc, entry.LastVerifiedFixedUtc.Value);
                sb.Append($" It was last verified fixed {verifiedText}.");
            }
        }

        sb.AppendLine();
    }

    private static void AppendWhatChanged(
        StringBuilder sb,
        string ruleId,
        RuleMemoryEntry entry,
        DateTime referenceUtc)
    {
        if (entry.SeverityHistory.Count < 2)
            return;

        sb.AppendLine();
        sb.AppendLine("**What changed**");

        var previous = entry.SeverityHistory[^2];
        var current = entry.SeverityHistory[^1];
        var previousTimeText = FormatRelativeTime(referenceUtc, previous.UtcTimestamp);
        var currentTimeText = FormatRelativeTime(referenceUtc, current.UtcTimestamp);

        sb.AppendLine($"**[{ruleId}]** severity escalated from {previous.Severity} to {current.Severity} (previous {previousTimeText}, latest {currentTimeText}).");
    }

    private static void AppendRootCause(StringBuilder sb, string ruleId)
    {
        sb.AppendLine();
        sb.AppendLine("**Root cause**");
        sb.AppendLine($"**[{ruleId}]** {RuleCategoryResolver.GetGuidance(ruleId)}");
    }

    private static string FormatTrend(RuleStatusTrend trend) => trend switch
    {
        RuleStatusTrend.Stable => "is stable",
        RuleStatusTrend.Improving => "is improving",
        RuleStatusTrend.Worsening => "is worsening",
        _ => "is still open"
    };

    private static string FormatRelativeTime(DateTime referenceUtc, DateTime eventUtc)
    {
        var days = (referenceUtc - eventUtc).TotalDays;
        return days switch
        {
            < 1 => "today",
            < 2 => "yesterday",
            < 7 => FormatUnit((int)Math.Round(days), "day"),
            < 30 => FormatUnit((int)Math.Round(days / 7), "week"),
            < 365 => FormatUnit((int)Math.Round(days / 30), "month"),
            _ => FormatUnit((int)Math.Round(days / 365), "year")
        };
    }

    private static string FormatUnit(int count, string unit)
    {
        var suffix = count == 1 ? unit : $"{unit}s";
        return $"{count} {suffix} ago";
    }
}
