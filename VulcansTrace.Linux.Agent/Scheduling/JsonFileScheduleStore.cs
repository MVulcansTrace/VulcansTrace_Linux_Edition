using System.Text.Json;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// A schedule store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileScheduleStore : IScheduleStore, IDisposable
{
    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<AuditSchedule> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileScheduleStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonFileScheduleStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonFileScheduleStore"/>.</returns>
    public static JsonFileScheduleStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileScheduleStore(Path.Combine(dir, "schedules.json"));
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
            var index = _entries.FindIndex(e => e.Id.Equals(schedule.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                _entries[index] = schedule;
            }
            else
            {
                _entries.Add(schedule);
            }
            SaveToDisk();
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
            var entries = JsonSerializer.Deserialize<List<AuditSchedule>>(json);
            if (entries != null)
            {
                _entries.Clear();
                _entries.AddRange(entries);
            }
        }
        catch
        {
            _persistenceWarning = "Could not load saved schedules. Previous schedules may be unavailable.";
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

            // Atomic write: write to temp file in same directory, then move into place
            var tempPath = _filePath + ".tmp";
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _filePath, overwrite: true);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save schedules to disk: {ex.Message}. Schedules will last only for this session.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
