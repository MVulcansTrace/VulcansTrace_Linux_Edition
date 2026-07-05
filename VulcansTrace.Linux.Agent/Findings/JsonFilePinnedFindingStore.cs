using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Findings;

/// <summary>
/// A pinned-finding store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFilePinnedFindingStore : IPinnedFindingStore, IDisposable
{
    private readonly JsonFilePersistence<List<PinnedFinding>> _persistence;
    private readonly IValidator<PinnedFinding> _validator = new PinnedFindingValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, PinnedFinding> _entries = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFilePinnedFindingStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFilePinnedFindingStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<PinnedFinding>>(filePath, JsonOptions, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFilePinnedFindingStore"/>.</returns>
    public static JsonFilePinnedFindingStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFilePinnedFindingStore(Path.Combine(dir, "pinned-findings.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public void Pin(PinnedFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, PinnedFinding>(_entries, StringComparer.OrdinalIgnoreCase)
            {
                [finding.Fingerprint] = finding
            };
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Unpin(string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, PinnedFinding>(_entries, StringComparer.OrdinalIgnoreCase);
            candidate.Remove(fingerprint);
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public bool IsPinned(string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        _lock.EnterReadLock();
        try
        {
            return _entries.ContainsKey(fingerprint);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PinnedFinding> GetAll()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.Values
                .OrderByDescending(f => f.PinnedAtUtc)
                .ToList();
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
                "pinned finding",
                f => f.Fingerprint);

            _entries.Clear();
            foreach (var finding in result.Valid)
            {
                _entries[finding.Fingerprint] = finding;
            }

            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved pinned findings; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load saved pinned findings (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(Dictionary<string, PinnedFinding> candidate)
    {
        var committed = false;
        try
        {
            var snapshot = candidate.Values.ToList();
            _validator.ValidateAllAndThrow(snapshot);

            _entries.Clear();
            foreach (var finding in snapshot)
            {
                _entries[finding.Fingerprint] = finding;
            }

            committed = true;
            _persistence.Save(snapshot);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = committed
                ? $"Could not save pinned findings to disk: {ex.Message}. Pins will last only for this session."
                : $"Could not save pinned findings to disk: {ex.Message}. Invalid pins were not saved.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
