using System.Text.Json;
using System.Text.Json.Serialization;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// A threat intel store that persists IOCs to a JSON file.
/// </summary>
public sealed class JsonFileThreatIntelStore : IThreatIntelStore, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly JsonFilePersistence<List<IocEntry>> _persistence;
    private readonly IValidator<IocEntry> _validator = new IocEntryValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, IocEntry> _entries = new(StringComparer.Ordinal);
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileThreatIntelStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileThreatIntelStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<IocEntry>>(filePath, JsonOptions, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileThreatIntelStore"/>.</returns>
    public static JsonFileThreatIntelStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileThreatIntelStore(Path.Combine(dir, "threat-intel.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

    /// <inheritdoc />
    public int Count
    {
        get
        {
            _lock.EnterReadLock();
            try { return _entries.Count; }
            finally { _lock.ExitReadLock(); }
        }
    }

    /// <inheritdoc />
    public void Import(IEnumerable<IocEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var incoming = entries.ToList();

        _lock.EnterWriteLock();
        try
        {
            var valid = _validator.PartitionValid(incoming, out var rejected);
            if (valid.Count == 0 && rejected.Count > 0)
            {
                _persistenceWarning = BuildImportWarning(0, rejected.Count);
                return;
            }

            var candidate = new Dictionary<string, IocEntry>(_entries, StringComparer.Ordinal);
            foreach (var entry in valid)
            {
                candidate[entry.StorageKey] = entry;
            }

            CommitCandidate(candidate, valid.Count, rejected.Count);
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
            PersistCurrentState("Threat intel changes will last only for this session.");
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public bool Remove(string storageKey)
    {
        ArgumentNullException.ThrowIfNull(storageKey);
        _lock.EnterWriteLock();
        try
        {
            var removed = _entries.Remove(storageKey);
            if (removed)
            {
                PersistCurrentState("Threat intel changes will last only for this session.");
            }
            return removed;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public int CountByType(IocType type)
    {
        var typeInt = (int)type;
        _lock.EnterReadLock();
        try
        {
            return _entries.Values.Count(e => (int)e.Type == typeInt);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<IocEntry> GetByType(IocType type)
    {
        var typeInt = (int)type;
        _lock.EnterReadLock();
        try
        {
            return _entries.Values.Where(e => (int)e.Type == typeInt).ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<IocEntry> GetAll()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.Values.ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "IOC",
                i => $"{i.Type}:{i.Value}");

            _entries.Clear();
            foreach (var entry in result.Valid)
            {
                _entries[entry.StorageKey] = entry;
            }

            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved threat intel; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved threat intel (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(Dictionary<string, IocEntry> candidate, int acceptedCount, int rejectedCount)
    {
        var committed = false;
        try
        {
            var snapshot = candidate.Values.ToList();
            _validator.ValidateAllAndThrow(snapshot);

            _entries.Clear();
            foreach (var entry in snapshot)
            {
                _entries[entry.StorageKey] = entry;
            }

            committed = true;
            _persistence.Save(snapshot);
            _persistenceWarning = rejectedCount > 0 ? BuildImportWarning(acceptedCount, rejectedCount) : null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = committed
                ? $"Could not save threat intel to disk: {ex.Message}. IOCs will last only for this session."
                : $"Could not save threat intel to disk: {ex.Message}. Invalid IOCs were not imported.";
        }
    }

    private void PersistCurrentState(string sessionOnlyMessage)
    {
        try
        {
            var snapshot = _entries.Values.ToList();
            _validator.ValidateAllAndThrow(snapshot);
            _persistence.Save(snapshot);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            // Clear/Remove mutate _entries before calling this method, so a save failure — whether
            // validation or I/O — leaves the in-memory change effective for this session only.
            // The exception message conveys the cause (invalid data vs. I/O error).
            _persistenceWarning = $"Could not save threat intel to disk: {ex.Message}. {sessionOnlyMessage}";
        }
    }

    private static string BuildImportWarning(int acceptedCount, int rejectedCount)
    {
        var acceptedPhrase = acceptedCount == 1 ? "1 IOC" : $"{acceptedCount} IOCs";
        var rejectedPhrase = rejectedCount == 1 ? "1 invalid IOC was skipped" : $"{rejectedCount} invalid IOCs were skipped";
        return $"Imported {acceptedPhrase}; {rejectedPhrase}.";
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
