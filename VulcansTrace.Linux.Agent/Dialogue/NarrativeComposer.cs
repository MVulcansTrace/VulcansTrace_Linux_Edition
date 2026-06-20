using System.Text;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
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
        var trajectory = ComposeTrajectory(result, sources);
        var proactiveAlerts = ComposeProactiveAlerts(result, sources);
        var attackChains = ComposeAttackChains(result, sources);
        var remediationWisdom = ComposeRemediationWisdom(result, sources);
        var memory = ComposeMemory(result, ruleHistory, result.UtcTimestamp, sources);
        var coverage = ComposeCoverage(result, entities);
        var nextSteps = ComposeNextSteps(result, sources);

        return new Narrative
        {
            Summary = summary,
            KeyFindingsParagraph = keyFindings,
            CorrelationsParagraph = correlations,
            TrajectoryParagraph = trajectory,
            ProactiveAlertsParagraph = proactiveAlerts,
            AttackChainsParagraph = attackChains,
            RemediationWisdomParagraph = remediationWisdom,
            MemoryParagraph = memory,
            CoverageParagraph = coverage,
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
            var daysText = FormatRelativeTime(referenceUtc, entry.FirstSeenUtc);

            var trendText = entry.Trend switch
            {
                RuleStatusTrend.Stable => "is still open",
                RuleStatusTrend.Worsening => "has worsened",
                RuleStatusTrend.Improving => "is improving",
                _ => "is still open"
            };

            sb.Append($"• **{entry.RuleId}** was first seen {daysText} and {trendText}.");

            if (entry.LastRemediationAttemptUtc.HasValue)
            {
                var attemptText = FormatRelativeTime(referenceUtc, entry.LastRemediationAttemptUtc.Value);
                sb.Append($" A remediation was attempted {attemptText}.");
            }

            if (entry.LastVerifiedFixedUtc.HasValue)
            {
                var verifiedText = FormatRelativeTime(referenceUtc, entry.LastVerifiedFixedUtc.Value);
                sb.Append($" It was verified fixed {verifiedText} but has returned.");
            }

            sb.AppendLine();
        }

        return sb.ToString().Trim();
    }

    private static string ComposeCoverage(AgentResult result, EntityFrame entities)
    {
        // Only surface coverage after targeted audits; full audits are intentionally comprehensive
        // and should not trigger a "you missed something" message.
        if (!IntentCategoryMap.IsTargetedAudit(result.Intent))
            return string.Empty;

        var checkedCategories = CategoryCoverageRecorder.GetCheckedCategories(entities.CheckedCategories);
        var uncheckedCategories = CategoryCoverageRecorder.GetUncheckedCategories(entities.CheckedCategories);

        if (uncheckedCategories.Count == 0)
            return string.Empty;

        // On the production same-turn path, Phase 9.5 has already recorded the current category, so
        // checkedCategories is non-empty. Guard the direct-call / default-frame case (tests, or a frame
        // restored before any audit this session) so we never index into an empty list.
        if (checkedCategories.Count == 0)
            return string.Empty;

        var auditedNames = checkedCategories.Count == 1
            ? checkedCategories[0]
            : string.Join(", ", checkedCategories.Take(checkedCategories.Count - 1)) + " and " + checkedCategories[^1];

        const int maxUncheckedExamples = 3;
        var exampleNames = uncheckedCategories.Take(maxUncheckedExamples).ToList();
        var remaining = uncheckedCategories.Count - exampleNames.Count;

        var uncheckedText = exampleNames.Count == 1
            ? exampleNames[0]
            : string.Join(", ", exampleNames.Take(exampleNames.Count - 1)) + " and " + exampleNames[^1];

        if (remaining > 0)
        {
            uncheckedText += $", plus {remaining} more";
        }

        var sb = new StringBuilder();
        sb.Append("**Coverage note:** ");
        sb.Append($"You've audited {auditedNames}. ");
        sb.Append($"You haven't checked {uncheckedText} yet. ");
        sb.Append("Running those checks would reduce your blind spots.");

        return sb.ToString().Trim();
    }

    private static string FormatRelativeTime(DateTime referenceUtc, DateTime eventUtc)
    {
        var days = (referenceUtc - eventUtc).TotalDays;
        return days switch
        {
            <= 0 => "today",
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

    private static string ComposeTrajectory(AgentResult result, HashSet<string> sources)
    {
        var trajectory = result.SystemTrajectory;
        if (trajectory == null || !trajectory.HasEnoughHistory)
            return string.Empty;

        var sb = new StringBuilder();
        sb.Append("**Trajectory:** ");

        var directionText = trajectory.Direction switch
        {
            TrajectoryDirection.Improving => "improving",
            TrajectoryDirection.Worsening => "worsening",
            TrajectoryDirection.Stable => "stable",
            _ => "stable"
        };

        sb.Append($"Across your recent audits, the system is trending {directionText}. ");

        var parts = new List<string>();
        if (trajectory.ImprovingCount > 0)
        {
            var examples = FormatExamples(trajectory.ImprovingRuleIds);
            sources.UnionWith(trajectory.ImprovingRuleIds);
            parts.Add($"{trajectory.ImprovingCount} rule(s) improving ({examples})");
        }

        if (trajectory.WorseningCount > 0)
        {
            var examples = FormatExamples(trajectory.WorseningRuleIds);
            sources.UnionWith(trajectory.WorseningRuleIds);
            parts.Add($"{trajectory.WorseningCount} rule(s) worsening ({examples})");
        }

        if (trajectory.StableCount > 0)
        {
            var examples = FormatExamples(trajectory.StableRuleIds);
            sources.UnionWith(trajectory.StableRuleIds);
            parts.Add($"{trajectory.StableCount} rule(s) stable ({examples})");
        }

        if (parts.Count > 0)
        {
            sb.Append(string.Join(", ", parts));
            sb.Append('.');
        }

        return sb.ToString().Trim();
    }

    private static string FormatExamples(IReadOnlyList<string> ruleIds)
    {
        if (ruleIds.Count == 0)
            return string.Empty;

        var examples = ruleIds.Take(3).Select(r => $"**{r}**");
        var suffix = ruleIds.Count > 3 ? ", …" : string.Empty;
        return string.Join(", ", examples) + suffix;
    }

    private static string ComposeProactiveAlerts(AgentResult result, HashSet<string> sources)
    {
        if (result.ProactiveAlerts.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Proactive alerts:**");

        foreach (var alert in result.ProactiveAlerts.Take(3))
        {
            sources.Add(alert.RuleId);
            var whenText = alert.DaysSinceVerifiedFixed switch
            {
                0 => "today",
                1 => "yesterday",
                _ => $"{alert.DaysSinceVerifiedFixed} days ago"
            };

            var guidance = string.IsNullOrWhiteSpace(alert.Guidance)
                ? "Check for automation, reboot-time defaults, configuration management, or base-image drift that may have restored the finding."
                : alert.Guidance;

            sb.Append($"• **[{alert.RuleId}]** returned after being verified fixed {whenText}. ");
            sb.Append(guidance);
            sb.AppendLine();
        }

        return sb.ToString().Trim();
    }

    private static string ComposeAttackChains(AgentResult result, HashSet<string> sources)
    {
        if (result.AttackChains.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Attack chain:**");

        foreach (var chain in result.AttackChains.Take(3))
        {
            foreach (var ruleId in chain.RuleIds)
            {
                sources.Add(ruleId);
            }

            sources.UnionWith(chain.SourcePatternIds);

            sb.AppendLine($"• {chain.Narrative}");
        }

        return sb.ToString().Trim();
    }

    private static string ComposeRemediationWisdom(AgentResult result, HashSet<string> sources)
    {
        if (result.RemediationWisdom.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        sb.AppendLine("**Remediation pattern:**");

        foreach (var wisdom in result.RemediationWisdom.Take(3))
        {
            sources.Add(wisdom.RuleId);
            sb.AppendLine($"• **[{wisdom.RuleId}]** has been fixed and returned {wisdom.CycleCount} times. {wisdom.Guidance}");
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
