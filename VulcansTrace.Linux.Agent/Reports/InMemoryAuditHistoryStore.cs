namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// An in-memory audit history store that does not persist to disk.
/// Useful as a fallback when file persistence is unavailable.
/// </summary>
public sealed class InMemoryAuditHistoryStore : IAuditHistoryStore
{
    private readonly List<AuditHistoryEntry> _entries = new();
    private readonly int _maxEntries;
    private readonly int _fullDetailCount;
    private readonly string? _persistenceWarning;
    private readonly ReaderWriterLockSlim _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryAuditHistoryStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning message explaining why persistence is unavailable.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    /// <param name="fullDetailCount">Number of newest entries to keep fully detailed; older retained entries are slimmed. Default is 5.</param>
    public InMemoryAuditHistoryStore(string? persistenceWarning = null, int maxEntries = 50, int fullDetailCount = 5)
    {
        _persistenceWarning = persistenceWarning;
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
        _fullDetailCount = fullDetailCount >= 0 ? fullDetailCount : throw new ArgumentOutOfRangeException(nameof(fullDetailCount), "Must be greater than or equal to zero.");
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public IReadOnlyList<AuditHistoryEntry> GetAll()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public void Append(AuditHistoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            _entries.Add(entry);
            Normalize();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Clear()
    {
        _lock.EnterWriteLock();
        try
        {
            _entries.Clear();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Update(AuditHistoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            var index = _entries.FindIndex(e => e.SnapshotId == entry.SnapshotId);
            if (index >= 0)
            {
                _entries[index] = entry;
                Normalize();
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    private void Normalize()
    {
        _entries.Sort((a, b) => b.TimestampUtc.CompareTo(a.TimestampUtc));

        for (var i = _fullDetailCount; i < _entries.Count; i++)
        {
            if (!_entries[i].IsSlimSummary)
            {
                _entries[i] = _entries[i].ToSlimSummary();
            }
        }

        while (_entries.Count > _maxEntries)
        {
            _entries.RemoveAt(_entries.Count - 1);
        }
    }
}
