using System.Text.Json;
using VulcansTrace.Linux.Agent;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// An audit history store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileAuditHistoryStore : IAuditHistoryStore, IDisposable
{
    private readonly string _filePath;
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
    public JsonFileAuditHistoryStore(string filePath, int maxEntries = 50, int fullDetailCount = 5)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
        _fullDetailCount = fullDetailCount >= 0 ? fullDetailCount : throw new ArgumentOutOfRangeException(nameof(fullDetailCount), "Must be greater than or equal to zero.");
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    /// <param name="fullDetailCount">Number of newest entries to keep fully detailed; older retained entries are slimmed. Default is 5.</param>
    /// <returns>A configured <see cref="JsonFileAuditHistoryStore"/>.</returns>
    public static JsonFileAuditHistoryStore CreateDefault(string? configDirectory = null, int maxEntries = 50, int fullDetailCount = 5)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileAuditHistoryStore(Path.Combine(dir, "audit-history.json"), maxEntries, fullDetailCount);
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
            SaveToDisk();
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
            SaveToDisk();
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
                SaveToDisk();
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

        // Slim older retained entries so the on-disk file stays bounded even when individual
        // audits carry large metadata (attack chains, capabilities, rule results, etc.). The
        // newest entries remain fully detailed because they are the most likely to be rehydrated
        // for follow-up intents such as ShowEvidence.
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

    private void LoadFromDisk()
    {
        try
        {
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var entries = JsonSerializer.Deserialize<List<AuditHistoryEntry>>(json);
            if (entries != null)
            {
                _entries.Clear();
                _entries.AddRange(entries);
                Normalize();
            }
        }
        catch
        {
            _persistenceWarning = "Could not load saved audit history. Previous audit summaries may be unavailable.";
            _entries.Clear();
        }
    }

    private void SaveToDisk()
    {
        try
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(_filePath, json);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save audit history to disk: {ex.Message}. History will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
