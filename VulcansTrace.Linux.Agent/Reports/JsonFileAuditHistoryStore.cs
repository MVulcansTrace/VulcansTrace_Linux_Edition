using System.Text.Json;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// An audit history store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileAuditHistoryStore : IAuditHistoryStore, IDisposable
{
    private readonly string _filePath;
    private readonly int _maxEntries;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<AuditHistoryEntry> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileAuditHistoryStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    public JsonFileAuditHistoryStore(string filePath, int maxEntries = 50)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 50.</param>
    /// <returns>A configured <see cref="JsonFileAuditHistoryStore"/>.</returns>
    public static JsonFileAuditHistoryStore CreateDefault(int maxEntries = 50)
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileAuditHistoryStore(Path.Combine(dir, "audit-history.json"), maxEntries);
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
