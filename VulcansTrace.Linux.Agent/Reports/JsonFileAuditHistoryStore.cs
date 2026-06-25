using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// An audit history store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileAuditHistoryStore : IAuditHistoryStore, IDisposable
{
    private readonly JsonFilePersistence<List<AuditHistoryEntry>> _persistence;
    private readonly IValidator<AuditHistoryEntry> _validator = new AuditHistoryEntryValidator();
    private readonly int _maxEntries;
    private readonly int _fullDetailCount;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<AuditHistoryEntry> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileAuditHistoryStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    /// <param name="fullDetailCount">Number of newest entries to keep fully detailed; older retained entries are slimmed. Default is 5.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileAuditHistoryStore(string filePath, int maxEntries = 50, int fullDetailCount = 5, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<AuditHistoryEntry>>(filePath, logSink: logSink);
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
        _fullDetailCount = fullDetailCount >= 0 ? fullDetailCount : throw new ArgumentOutOfRangeException(nameof(fullDetailCount), "Must be greater than or equal to zero.");
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    /// <param name="fullDetailCount">Number of newest entries to keep fully detailed; older retained entries are slimmed. Default is 5.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileAuditHistoryStore"/>.</returns>
    public static JsonFileAuditHistoryStore CreateDefault(string? configDirectory = null, int maxEntries = 50, int fullDetailCount = 5, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileAuditHistoryStore(Path.Combine(dir, "audit-history.json"), maxEntries, fullDetailCount, logSink);
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
            var candidate = _entries.ToList();
            candidate.Add(entry);
            Normalize(candidate);
            CommitCandidate(candidate);
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
            CommitCandidate(new List<AuditHistoryEntry>());
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
                var candidate = _entries.ToList();
                candidate[index] = entry;
                Normalize(candidate);
                CommitCandidate(candidate);
            }
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    private void Normalize() => Normalize(_entries);

    private void Normalize(List<AuditHistoryEntry> entries)
    {
        entries.Sort((a, b) => b.TimestampUtc.CompareTo(a.TimestampUtc));

        // Slim older retained entries so the on-disk file stays bounded even when individual
        // audits carry large metadata (attack chains, capabilities, rule results, etc.). The
        // newest entries remain fully detailed because they are the most likely to be rehydrated
        // for follow-up intents such as ShowEvidence.
        for (var i = _fullDetailCount; i < entries.Count; i++)
        {
            if (!entries[i].IsSlimSummary)
            {
                entries[i] = entries[i].ToSlimSummary();
            }
        }

        while (entries.Count > _maxEntries)
        {
            entries.RemoveAt(entries.Count - 1);
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "audit",
                a => a.SnapshotId);

            _entries.Clear();
            _entries.AddRange(result.Valid);
            Normalize();
            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved audit history; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved audit history (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(List<AuditHistoryEntry> candidate)
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
                ? $"Could not save audit history to disk: {ex.Message}. History will last only for this session."
                : $"Could not save audit history to disk: {ex.Message}. Invalid history entries were not saved.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
