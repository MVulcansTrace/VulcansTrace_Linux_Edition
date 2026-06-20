using VulcansTrace.Linux.Agent.Memory;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Determines the explanation depth tier for a rule from its persistent memory entry.
/// The function is deterministic and uses only immutable fields of <see cref="RuleMemoryEntry"/>.
/// </summary>
public static class ExplanationDepthResolver
{
    /// <summary>
    /// Minimum number of retained severity snapshots required before a rule is considered familiar.
    /// </summary>
    internal const int MinHistoryLengthForFamiliar = 2;

    /// <summary>
    /// Minimum number of closed remediation cycles required before a rule is considered recurring.
    /// </summary>
    internal const int MinClosedCyclesForRecurring = 2;

    /// <summary>
    /// Resolves the explanation depth for the provided rule history entry.
    /// </summary>
    /// <param name="entry">The rule's memory entry, or null if the rule has no history.</param>
    /// <returns>The depth tier to use when explaining the rule.</returns>
    public static ExplanationDepth Resolve(RuleMemoryEntry? entry)
    {
        if (entry == null)
            return ExplanationDepth.Standard;

        var historyLength = entry.SeverityHistory.Count;
        if (historyLength < MinHistoryLengthForFamiliar)
            return ExplanationDepth.Standard;

        if (entry.Trend == RuleStatusTrend.Worsening)
            return ExplanationDepth.Escalating;

        var closedCycles = entry.RemediationCycles.Count(c => c.IsClosed);
        if (closedCycles >= MinClosedCyclesForRecurring)
            return ExplanationDepth.Recurring;

        return ExplanationDepth.Familiar;
    }
}
