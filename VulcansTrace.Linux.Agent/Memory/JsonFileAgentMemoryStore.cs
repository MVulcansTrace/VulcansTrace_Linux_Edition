using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// A file-backed memory store that persists the agent's conversation memory snapshot to JSON.
/// </summary>
public sealed class JsonFileAgentMemoryStore : IAgentMemoryStore, IDisposable
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private AgentMemorySnapshot? _snapshot;
    private string? _persistenceWarning;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileAgentMemoryStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    public JsonFileAgentMemoryStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <returns>A configured <see cref="JsonFileAgentMemoryStore"/>.</returns>
    public static JsonFileAgentMemoryStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileAgentMemoryStore(Path.Combine(dir, "agent-memory.json"));
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public AgentMemorySnapshot? Load()
    {
        _lock.Wait();
        try
        {
            return _snapshot;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc />
    public async Task SaveAsync(AgentMemorySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        await _lock.WaitAsync().ConfigureAwait(false);
        try
        {
            _snapshot = snapshot;
            await SaveToDiskAsync().ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var snapshot = JsonSerializer.Deserialize<AgentMemorySnapshot>(json, _jsonOptions);
            if (snapshot != null)
            {
                _snapshot = snapshot;
            }
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load saved agent memory: {ex.Message}";
            _snapshot = null;
        }
    }

    private async Task SaveToDiskAsync()
    {
        try
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(_snapshot, _jsonOptions);
            var tempPath = _filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json).ConfigureAwait(false);
            File.Move(tempPath, _filePath, overwrite: true);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not save agent memory: {ex.Message}";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _lock.Dispose();
    }
}
