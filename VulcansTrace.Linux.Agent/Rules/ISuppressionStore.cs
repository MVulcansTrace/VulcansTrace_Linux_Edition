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
    /// Checks whether a finding is suppressed by rule/target or by fingerprint.
    /// </summary>
    /// <param name="ruleId">The rule ID.</param>
    /// <param name="target">The target.</param>
    /// <param name="fingerprint">The stable fingerprint of the finding.</param>
    /// <returns>True if suppressed; otherwise, false.</returns>
    bool IsSuppressed(string ruleId, string target, string fingerprint);

    /// <summary>
    /// Gets all active suppression entries.
    /// </summary>
    IReadOnlyList<SuppressionEntry> GetAll();

    /// <summary>
    /// Gets all suppression entries including expired ones.
    /// </summary>
    IReadOnlyList<SuppressionEntry> GetAllRaw();

    /// <summary>
    /// Removes suppression entries expired longer than the retention window and returns the count removed.
    /// </summary>
    int PruneExpired();

    /// <summary>
    /// Gets the latest persistence warning, if suppressions could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
