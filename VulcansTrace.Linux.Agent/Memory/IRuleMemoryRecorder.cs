using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Records per-rule history from audit results into persistent memory entries.
/// </summary>
public interface IRuleMemoryRecorder
{
    /// <summary>
    /// Updates rule history entries from the provided audit result.
    /// </summary>
    /// <param name="result">The audit result to record.</param>
    /// <param name="existing">The current rule history dictionary.</param>
    /// <returns>An updated rule history dictionary.</returns>
    IReadOnlyDictionary<string, RuleMemoryEntry> Record(AgentResult result, IReadOnlyDictionary<string, RuleMemoryEntry> existing);

    /// <summary>
    /// Marks the specified rules as verified fixed at the given timestamp.
    /// </summary>
    /// <param name="ruleIds">The rule IDs to mark as fixed.</param>
    /// <param name="timestampUtc">The verification timestamp.</param>
    /// <param name="existing">The current rule history dictionary.</param>
    /// <returns>An updated rule history dictionary.</returns>
    IReadOnlyDictionary<string, RuleMemoryEntry> MarkVerifiedFixed(
        IEnumerable<string> ruleIds,
        DateTime timestampUtc,
        IReadOnlyDictionary<string, RuleMemoryEntry> existing);

    /// <summary>
    /// Marks the specified rules as having a remediation attempted at the given timestamp.
    /// </summary>
    /// <param name="ruleIds">The rule IDs to mark as attempted.</param>
    /// <param name="timestampUtc">The remediation attempt timestamp.</param>
    /// <param name="existing">The current rule history dictionary.</param>
    /// <returns>An updated rule history dictionary.</returns>
    IReadOnlyDictionary<string, RuleMemoryEntry> MarkRemediationAttempt(
        IEnumerable<string> ruleIds,
        DateTime timestampUtc,
        IReadOnlyDictionary<string, RuleMemoryEntry> existing);
}

