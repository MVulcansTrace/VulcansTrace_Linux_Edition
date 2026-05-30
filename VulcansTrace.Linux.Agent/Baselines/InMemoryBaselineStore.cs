using System.Threading;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// An in-memory baseline store that does not persist to disk.
/// Useful as a fallback when file persistence is unavailable.
/// </summary>
public sealed class InMemoryBaselineStore : IBaselineStore
{
    private readonly List<BaselineEntry> _entries = new();
    private readonly string? _persistenceWarning;
    private readonly ReaderWriterLockSlim _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryBaselineStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning message explaining why persistence is unavailable.</param>
    public InMemoryBaselineStore(string? persistenceWarning = null)
    {
        _persistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public IReadOnlyList<BaselineEntry> GetAll()
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
    public BaselineEntry? GetActive(AgentIntent intent)
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.FirstOrDefault(e => e.Intent == intent && e.IsActive);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public void Save(BaselineEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            var index = _entries.FindIndex(e => e.BaselineId == entry.BaselineId);
            if (index >= 0)
            {
                _entries[index] = entry;
            }
            else
            {
                _entries.Add(entry);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Delete(string baselineId)
    {
        _lock.EnterWriteLock();
        try
        {
            _entries.RemoveAll(e => e.BaselineId == baselineId);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void SetActive(string baselineId)
    {
        _lock.EnterWriteLock();
        try
        {
            var target = _entries.FirstOrDefault(e => e.BaselineId == baselineId);
            if (target == null)
                return;

            for (var i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Intent == target.Intent)
                {
                    _entries[i] = _entries[i] with { IsActive = false };
                }
            }

            var targetIndex = _entries.FindIndex(e => e.BaselineId == baselineId);
            if (targetIndex >= 0)
            {
                _entries[targetIndex] = _entries[targetIndex] with { IsActive = true };
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }
}
