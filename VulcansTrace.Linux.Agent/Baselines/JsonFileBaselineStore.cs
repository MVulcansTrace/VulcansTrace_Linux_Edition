using System.Text.Json;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// A baseline store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileBaselineStore : IBaselineStore, IDisposable
{
    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<BaselineEntry> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileBaselineStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonFileBaselineStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonFileBaselineStore"/>.</returns>
    public static JsonFileBaselineStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileBaselineStore(Path.Combine(dir, "baselines.json"));
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
            SaveToDisk();
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
            SaveToDisk();
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

            SaveToDisk();
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
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var entries = JsonSerializer.Deserialize<List<BaselineEntry>>(json);
            if (entries != null)
            {
                _entries.Clear();
                _entries.AddRange(entries);
            }
        }
        catch
        {
            _persistenceWarning = "Could not load saved baselines. Previous baselines may be unavailable.";
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
            _persistenceWarning = $"Could not save baselines to disk: {ex.Message}. Baselines will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
