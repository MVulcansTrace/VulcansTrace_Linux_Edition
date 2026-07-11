using System.Text.Json;
using System.Text.Json.Serialization;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// A file-backed memory store that persists the agent's conversation memory snapshot to JSON.
/// </summary>
public sealed class JsonFileAgentMemoryStore : IAgentMemoryStore, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly JsonFilePersistence<AgentMemorySnapshot> _persistence;
    private readonly IValidator<AgentMemorySnapshot> _validator = new AgentMemorySnapshotValidator();
    private readonly SemaphoreSlim _lock = new(1, 1);

    private AgentMemorySnapshot? _snapshot;
    private string? _persistenceWarning;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileAgentMemoryStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileAgentMemoryStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<AgentMemorySnapshot>(filePath, JsonOptions, useAtomicWrite: true, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileAgentMemoryStore"/>.</returns>
    public static JsonFileAgentMemoryStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileAgentMemoryStore(Path.Combine(dir, "agent-memory.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

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
            await SaveToDiskAsync(snapshot).ConfigureAwait(false);
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
            var snapshot = _persistence.Load();
            if (snapshot != null)
            {
                _validator.ValidateAndThrow(snapshot);

                // System.Text.Json does not preserve the dictionary comparer. Rebuild with
                // OrdinalIgnoreCase and normalized uppercase keys so rule lookups remain
                // case-insensitive after a restart.
                if (snapshot.RuleHistory.Count > 0)
                {
                    var normalized = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);
                    foreach (var kvp in snapshot.RuleHistory)
                    {
                        var upperKey = kvp.Key.ToUpperInvariant();
                        normalized[upperKey] = kvp.Value with { RuleId = upperKey };
                    }

                    snapshot = snapshot with { RuleHistory = normalized };
                }

                _snapshot = snapshot;
            }
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved agent memory; the file has been quarantined. {ex.Message}";
            _snapshot = null;
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved agent memory (will retry next start): {ex.Message}";
            _snapshot = null;
        }
    }

    private async Task SaveToDiskAsync(AgentMemorySnapshot snapshot)
    {
        var committed = false;
        try
        {
            _validator.ValidateAndThrow(snapshot);
            _snapshot = snapshot;
            committed = true;
            await _persistence.SaveAsync(snapshot).ConfigureAwait(false);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = committed
                ? $"Could not save agent memory: {ex.Message}"
                : $"Could not save agent memory: {ex.Message}. Invalid memory snapshot was not saved.";
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
