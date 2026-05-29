namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Defines storage and retrieval of audit history entries.
/// </summary>
public interface IAuditHistoryStore
{
    /// <summary>
    /// Gets all stored audit history entries, ordered newest first.
    /// </summary>
    IReadOnlyList<AuditHistoryEntry> GetAll();

    /// <summary>
    /// Appends an entry to the store. The store may prune older entries
    /// to respect its configured maximum capacity.
    /// </summary>
    /// <param name="entry">The entry to append.</param>
    void Append(AuditHistoryEntry entry);

    /// <summary>
    /// Clears all stored audit history entries.
    /// </summary>
    void Clear();

    /// <summary>
    /// Updates an existing entry matched by <see cref="AuditHistoryEntry.SnapshotId"/>.
    /// If no matching entry exists, the operation is a no-op.
    /// </summary>
    /// <param name="entry">The updated entry.</param>
    void Update(AuditHistoryEntry entry);

    /// <summary>
    /// Gets the latest persistence warning, if history could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
