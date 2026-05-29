using System.Text.Json;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A suppression store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileSuppressionStore : ISuppressionStore, IDisposable
{
    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, SuppressionEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileSuppressionStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonFileSuppressionStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonFileSuppressionStore"/>.</returns>
    public static JsonFileSuppressionStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileSuppressionStore(Path.Combine(dir, "suppressions.json"));
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public void Add(SuppressionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            _entries[entry.MatchKey] = entry;
            SaveToDisk();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Remove(string ruleId, string target)
    {
        _lock.EnterWriteLock();
        try
        {
            _entries.Remove($"{ruleId}|{target}");
            SaveToDisk();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public bool IsSuppressed(string ruleId, string target)
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.ContainsKey($"{ruleId}|{target}");
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<SuppressionEntry> GetAll()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.Values.OrderByDescending(e => e.CreatedAt).ToList();
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
            var entries = JsonSerializer.Deserialize<List<SuppressionEntry>>(json);
            if (entries != null)
            {
                foreach (var entry in entries)
                {
                    _entries[entry.MatchKey] = entry;
                }
            }
        }
        catch
        {
            // If loading fails, start with an empty store
            _persistenceWarning = "Could not load saved suppressions. Accepted risks will continue in memory, but previous suppressions may be unavailable.";
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
                WriteIndented = true
            });
            File.WriteAllText(_filePath, json);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            // If saving fails, the in-memory store still works
            _persistenceWarning = $"Could not save suppressions to disk: {ex.Message}. Accepted risks will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
