using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// A schedule store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileScheduleStore : IScheduleStore, IDisposable
{
    private readonly JsonFilePersistence<List<AuditSchedule>> _persistence;
    private readonly IValidator<AuditSchedule> _validator = new AuditScheduleValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<AuditSchedule> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileScheduleStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileScheduleStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<AuditSchedule>>(filePath, useAtomicWrite: true, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the VulcansTrace config directory (XDG_CONFIG_HOME or ~/.config by default).
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory (e.g. a per-test temp dir).</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileScheduleStore"/>.</returns>
    public static JsonFileScheduleStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileScheduleStore(Path.Combine(dir, "schedules.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

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
            var candidate = _entries.ToList();
            var index = candidate.FindIndex(e => e.Id.Equals(schedule.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                candidate[index] = schedule;
            }
            else
            {
                candidate.Add(schedule);
            }

            CommitCandidate(candidate);
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
            var candidate = _entries.ToList();
            candidate.RemoveAll(e => e.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "schedule",
                s => s.Id);

            _entries.Clear();
            _entries.AddRange(result.Valid);
            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved schedules; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved schedules (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(List<AuditSchedule> candidate)
    {
        var committed = false;
        try
        {
            _validator.ValidateAllAndThrow(candidate);
            _entries.Clear();
            _entries.AddRange(candidate);

            committed = true;
            _persistence.Save(candidate);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = committed
                ? $"Could not save schedules to disk: {ex.Message}. Schedules will last only for this session."
                : $"Could not save schedules to disk: {ex.Message}. Invalid schedules were not saved.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
