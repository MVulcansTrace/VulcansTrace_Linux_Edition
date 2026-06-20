using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Detects rules that have been remediated and returned multiple times,
/// producing deterministic senior-analyst-style guidance.
/// </summary>
public sealed class RemediationWisdomAnalyzer
{
    /// <summary>
    /// Minimum number of completed remediation cycles before wisdom is surfaced.
    /// </summary>
    internal const int MinCyclesForWisdom = 2;

    /// <summary>
    /// Analyzes current findings and their remediation cycle history.
    /// </summary>
    public IReadOnlyList<RemediationWisdom> Analyze(
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(ruleHistory);

        var wisdom = new List<RemediationWisdom>();

        var currentRuleIds = findings
            .Select(f => f.RuleId)
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in currentRuleIds)
        {
            if (!ruleHistory.TryGetValue(ruleId!, out var entry))
                continue;

            var closedCycles = entry.RemediationCycles.Where(c => c.IsClosed).ToList();
            if (closedCycles.Count < MinCyclesForWisdom)
                continue;

            var mostRecent = closedCycles.OrderByDescending(c => c.VerifiedFixedUtc).First();

            wisdom.Add(new RemediationWisdom
            {
                RuleId = ruleId!,
                CycleCount = closedCycles.Count,
                LastVerifiedFixedUtc = mostRecent.VerifiedFixedUtc!.Value,
                Guidance = BuildGuidance(ruleId!)
            });
        }

        return wisdom;
    }

    private static string BuildGuidance(string ruleId) => RuleCategoryResolver.GetGuidance(ruleId);
}
