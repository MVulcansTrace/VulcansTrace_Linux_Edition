namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// Defines storage and retrieval of analyst action audit log entries.
/// </summary>
public interface IAnalystActionStore
{
    /// <summary>
    /// Raised whenever the store's contents change (an entry is appended or the log is cleared),
    /// so views can refresh. Always raised off the store's write lock, but may fire on any thread;
    /// subscribers must marshal to their own thread (e.g. the UI dispatcher) before touching UI state.
    /// </summary>
    event EventHandler? Changed;

    /// <summary>
    /// Gets all stored analyst action entries, ordered newest first.
    /// </summary>
    IReadOnlyList<AnalystActionEntry> GetAll();

    /// <summary>
    /// Appends an entry to the store. The store may prune older entries
    /// to respect its configured maximum capacity.
    /// </summary>
    void Append(AnalystActionEntry entry);

    /// <summary>
    /// Clears all stored analyst action entries.
    /// </summary>
    void Clear();

    /// <summary>
    /// Gets the latest persistence warning, if actions could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
