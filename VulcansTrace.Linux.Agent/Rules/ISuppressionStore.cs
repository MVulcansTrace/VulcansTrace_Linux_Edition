namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Defines storage and retrieval of rule suppression entries.
/// </summary>
public interface ISuppressionStore
{
    /// <summary>
    /// Adds a suppression entry.
    /// </summary>
    /// <param name="entry">The entry to add.</param>
    void Add(SuppressionEntry entry);

    /// <summary>
    /// Removes a suppression entry by rule ID and target.
    /// </summary>
    /// <param name="ruleId">The rule ID.</param>
    /// <param name="target">The target.</param>
    void Remove(string ruleId, string target);

    /// <summary>
    /// Checks whether a finding is suppressed.
    /// </summary>
    /// <param name="ruleId">The rule ID.</param>
    /// <param name="target">The target.</param>
    /// <returns>True if suppressed; otherwise, false.</returns>
    bool IsSuppressed(string ruleId, string target);

    /// <summary>
    /// Gets all active suppression entries.
    /// </summary>
    IReadOnlyList<SuppressionEntry> GetAll();

    /// <summary>
    /// Gets the latest persistence warning, if suppressions could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
