using System.Threading;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// In-memory fallback schedule store when JSON persistence is unavailable.
/// </summary>
public sealed class InMemoryScheduleStore : IScheduleStore, IDisposable
{
    private readonly List<AuditSchedule> _entries = new();
    private readonly ReaderWriterLockSlim _lock = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryScheduleStore"/> class.
    /// </summary>
    /// <param name="warning">Optional persistence warning message.</param>
    public InMemoryScheduleStore(string? warning = null)
    {
        PersistenceWarning = warning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public IReadOnlyList<AuditSchedule> GetAll()
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
    public AuditSchedule? GetById(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        _lock.EnterReadLock();
        try
        {
            return _entries.FirstOrDefault(e => e.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public void Save(AuditSchedule schedule)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        _lock.EnterWriteLock();
        try
        {
            var index = _entries.FindIndex(e => e.Id.Equals(schedule.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                _entries[index] = schedule;
            }
            else
            {
                _entries.Add(schedule);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Delete(string id)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        _lock.EnterWriteLock();
        try
        {
            _entries.RemoveAll(e => e.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
