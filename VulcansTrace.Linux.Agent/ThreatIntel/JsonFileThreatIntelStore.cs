using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// A threat intel store that persists IOCs to a JSON file.
/// </summary>
public sealed class JsonFileThreatIntelStore : IThreatIntelStore, IDisposable
{
    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, IocEntry> _entries = new(StringComparer.Ordinal);
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileThreatIntelStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonFileThreatIntelStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonFileThreatIntelStore"/>.</returns>
    public static JsonFileThreatIntelStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileThreatIntelStore(Path.Combine(dir, "threat-intel.json"));
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

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
        _lock.EnterWriteLock();
        try
        {
            foreach (var entry in entries)
            {
                _entries[entry.StorageKey] = entry;
            }
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
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var entries = JsonSerializer.Deserialize<List<IocEntry>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            if (entries != null)
            {
                foreach (var entry in entries)
                {
                    _entries[entry.StorageKey] = entry;
                }
            }
        }
        catch
        {
            _persistenceWarning = "Could not load saved threat intel. IOCs will continue in memory, but previous imports may be unavailable.";
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

            var json = JsonSerializer.Serialize(_entries.Values.ToList(), new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });
            File.WriteAllText(_filePath, json);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save threat intel to disk: {ex.Message}. IOCs will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
