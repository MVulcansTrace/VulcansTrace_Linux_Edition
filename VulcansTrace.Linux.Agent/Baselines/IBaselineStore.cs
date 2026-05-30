using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// Defines storage and retrieval of configuration baselines.
/// </summary>
public interface IBaselineStore
{
    /// <summary>
    /// Gets all stored baseline entries.
    /// </summary>
    IReadOnlyList<BaselineEntry> GetAll();

    /// <summary>
    /// Gets the active baseline for the specified intent, or null if none exists.
    /// </summary>
    /// <param name="intent">The audit intent to look up.</param>
    BaselineEntry? GetActive(AgentIntent intent);

    /// <summary>
    /// Saves a baseline entry. If a baseline with the same <see cref="BaselineEntry.BaselineId"/>
    /// already exists, it is replaced.
    /// </summary>
    /// <param name="entry">The baseline entry to save.</param>
    void Save(BaselineEntry entry);

    /// <summary>
    /// Deletes the baseline with the specified ID.
    /// </summary>
    /// <param name="baselineId">The baseline ID to delete.</param>
    void Delete(string baselineId);

    /// <summary>
    /// Sets the specified baseline as active for its intent, deactivating any other
    /// baseline for the same intent.
    /// </summary>
    /// <param name="baselineId">The baseline ID to activate.</param>
    void SetActive(string baselineId);

    /// <summary>
    /// Gets the latest persistence warning, if baselines could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
