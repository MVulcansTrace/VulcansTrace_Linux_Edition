using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// A baseline store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileBaselineStore : IBaselineStore, IDisposable
{
    private readonly JsonFilePersistence<List<BaselineEntry>> _persistence;
    private readonly IValidator<BaselineEntry> _validator = new BaselineEntryValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<BaselineEntry> _entries = new();
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileBaselineStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileBaselineStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<BaselineEntry>>(filePath, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="configDirectory">Optional explicit config directory.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileBaselineStore"/>.</returns>
    public static JsonFileBaselineStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileBaselineStore(Path.Combine(dir, "baselines.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

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
            var candidate = _entries.ToList();
            var index = candidate.FindIndex(e => e.BaselineId == entry.BaselineId);
            if (index >= 0)
            {
                candidate[index] = entry;
            }
            else
            {
                candidate.Add(entry);
            }

            CommitCandidate(candidate);
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
            var candidate = _entries.ToList();
            candidate.RemoveAll(e => e.BaselineId == baselineId);
            CommitCandidate(candidate);
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

            var candidate = _entries.ToList();
            for (var i = 0; i < candidate.Count; i++)
            {
                if (candidate[i].Intent == target.Intent)
                {
                    candidate[i] = candidate[i] with { IsActive = false };
                }
            }

            var targetIndex = candidate.FindIndex(e => e.BaselineId == baselineId);
            if (targetIndex >= 0)
            {
                candidate[targetIndex] = candidate[targetIndex] with { IsActive = true };
            }

            CommitCandidate(candidate);
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
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "baseline",
                b => b.BaselineId);

            _entries.Clear();
            _entries.AddRange(result.Valid);
            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved baselines; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved baselines (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(List<BaselineEntry> candidate)
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
                ? $"Could not save baselines to disk: {ex.Message}. Baselines will last only for this session."
                : $"Could not save baselines to disk: {ex.Message}. Invalid baselines were not saved.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
