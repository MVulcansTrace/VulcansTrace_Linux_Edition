using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Aggregates per-rule trend data into a system-level trajectory story.
/// </summary>
public sealed class SystemTrajectoryAnalyzer
{
    /// <summary>
    /// Computes the system trajectory from the current findings and rule history.
    /// </summary>
    public SystemTrajectory Analyze(
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(ruleHistory);

        var currentRuleIds = findings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var improving = new List<string>();
        var worsening = new List<string>();
        var stable = new List<string>();

        var weightedDelta = 0;

        foreach (var entry in ruleHistory.Values
            .Where(e => !string.IsNullOrWhiteSpace(e.RuleId))
            .OrderBy(e => e.RuleId, StringComparer.OrdinalIgnoreCase))
        {
            var isCurrentlyFailing = currentRuleIds.Contains(entry.RuleId);
            if (!isCurrentlyFailing && !entry.LastVerifiedFixedUtc.HasValue)
                continue;

            var weight = SeverityWeight(entry.LastSeverity);

            if (!isCurrentlyFailing)
            {
                improving.Add(entry.RuleId);
                weightedDelta += Math.Max(1, weight);
                continue;
            }

            if (entry.SeverityHistory.Count < 2)
                continue;

            switch (entry.Trend)
            {
                case RuleStatusTrend.Improving:
                    improving.Add(entry.RuleId);
                    weightedDelta += weight;
                    break;
                case RuleStatusTrend.Worsening:
                    worsening.Add(entry.RuleId);
                    weightedDelta -= weight;
                    break;
                case RuleStatusTrend.Stable:
                    stable.Add(entry.RuleId);
                    break;
            }
        }

        var direction = ComputeDirection(improving.Count, worsening.Count, stable.Count, weightedDelta);

        return new SystemTrajectory
        {
            Direction = direction,
            ImprovingCount = improving.Count,
            WorseningCount = worsening.Count,
            StableCount = stable.Count,
            WeightedDelta = weightedDelta,
            ImprovingRuleIds = improving,
            WorseningRuleIds = worsening,
            StableRuleIds = stable
        };
    }

    private static TrajectoryDirection ComputeDirection(int improving, int worsening, int stable, int weightedDelta)
    {
        var total = improving + worsening + stable;
        if (total < 2)
            return TrajectoryDirection.InsufficientHistory;

        if (weightedDelta > 0)
            return TrajectoryDirection.Improving;

        if (weightedDelta < 0)
            return TrajectoryDirection.Worsening;

        return TrajectoryDirection.Stable;
    }

    private static int SeverityWeight(Severity severity) => severity switch
    {
        Severity.Critical => 4,
        Severity.High => 3,
        Severity.Medium => 2,
        Severity.Low => 1,
        Severity.Info => 0,
        _ => 0
    };
}
