namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// An in-memory analyst action store that does not persist to disk.
/// Useful as a fallback when file persistence is unavailable.
/// </summary>
public sealed class InMemoryAnalystActionStore : IAnalystActionStore
{
    private readonly List<AnalystActionEntry> _entries = new();
    private readonly int _maxEntries;
    private readonly string? _persistenceWarning;
    private readonly ReaderWriterLockSlim _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryAnalystActionStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning message explaining why persistence is unavailable.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 1000.</param>
    public InMemoryAnalystActionStore(string? persistenceWarning = null, int maxEntries = 1000)
    {
        _persistenceWarning = persistenceWarning;
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
    }

    /// <inheritdoc />
    public event EventHandler? Changed;

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public IReadOnlyList<AnalystActionEntry> GetAll()
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
    public void Append(AnalystActionEntry entry)
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

        OnChanged();
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

        OnChanged();
    }

    /// <summary>Raises <see cref="Changed"/> off the write lock so subscribers can safely re-read.</summary>
    private void OnChanged() => Changed?.Invoke(this, EventArgs.Empty);

    private void Normalize()
    {
        _entries.Sort((a, b) => b.TimestampUtc.CompareTo(a.TimestampUtc));

        while (_entries.Count > _maxEntries)
        {
            _entries.RemoveAt(_entries.Count - 1);
        }
    }
}
