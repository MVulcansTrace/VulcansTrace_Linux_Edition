using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A suppression store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileSuppressionStore : ISuppressionStore, IDisposable
{
    private readonly JsonFilePersistence<List<SuppressionEntry>> _persistence;
    private readonly IValidator<SuppressionEntry> _validator = new SuppressionEntryValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, SuppressionEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileSuppressionStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileSuppressionStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<SuppressionEntry>>(filePath, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileSuppressionStore"/>.</returns>
    public static JsonFileSuppressionStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileSuppressionStore(Path.Combine(dir, "suppressions.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

    /// <inheritdoc />
    public void Add(SuppressionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, SuppressionEntry>(_entries, StringComparer.OrdinalIgnoreCase)
            {
                [entry.StorageKey] = entry
            };
            CommitCandidate(candidate);
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
            var candidate = new Dictionary<string, SuppressionEntry>(_entries, StringComparer.OrdinalIgnoreCase);
            candidate.Remove($"{ruleId}|{target}");
            var keysToRemove = candidate
                .Where(kvp => kvp.Value.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase)
                           && kvp.Value.Target.Equals(target, StringComparison.OrdinalIgnoreCase))
                .Select(kvp => kvp.Key)
                .ToList();
            foreach (var key in keysToRemove)
            {
                candidate.Remove(key);
            }
            CommitCandidate(candidate);
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
            if (!_entries.TryGetValue($"{ruleId}|{target}", out var entry))
                return false;

            if (!string.IsNullOrEmpty(entry.Fingerprint))
                return false;

            if (entry.ExpiresAt.HasValue && entry.ExpiresAt.Value <= DateTime.UtcNow)
                return false;

            return true;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public bool IsSuppressed(string ruleId, string target, string fingerprint)
    {
        _lock.EnterReadLock();
        try
        {
            if (!string.IsNullOrEmpty(fingerprint))
            {
                if (_entries.TryGetValue($"{ruleId}|{fingerprint}", out var fpEntry))
                {
                    if (!fpEntry.ExpiresAt.HasValue || fpEntry.ExpiresAt.Value > DateTime.UtcNow)
                        return true;
                }
            }

            if (!_entries.TryGetValue($"{ruleId}|{target}", out var entry))
                return false;

            // Only fall back to rule+target match if the entry has no fingerprint
            // (i.e., it is an old-style suppression).
            if (!string.IsNullOrEmpty(entry.Fingerprint))
                return false;

            if (entry.ExpiresAt.HasValue && entry.ExpiresAt.Value <= DateTime.UtcNow)
                return false;

            return true;
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
            return _entries.Values
                .Where(e => !e.ExpiresAt.HasValue || e.ExpiresAt.Value > DateTime.UtcNow)
                .OrderByDescending(e => e.CreatedAt)
                .ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<SuppressionEntry> GetAllRaw()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.Values
                .OrderByDescending(e => e.CreatedAt)
                .ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public int PruneExpired()
    {
        _lock.EnterWriteLock();
        try
        {
            var cutoff = DateTime.UtcNow.AddDays(-SuppressionRetentionPolicy.ExpiredRetentionDays);
            var expiredKeys = _entries
                .Where(kvp => kvp.Value.ExpiresAt.HasValue && kvp.Value.ExpiresAt.Value <= cutoff)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredKeys)
            {
                _entries.Remove(key);
            }

            if (expiredKeys.Count > 0)
            {
                PersistCurrentState();
            }

            return expiredKeys.Count;
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
                "suppression",
                s => s.StorageKey);

            _entries.Clear();
            foreach (var entry in result.Valid)
            {
                _entries[entry.StorageKey] = entry;
            }

            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved suppressions; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved suppressions (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(Dictionary<string, SuppressionEntry> candidate)
    {
        var committed = false;
        try
        {
            var snapshot = candidate.Values
                .GroupBy(entry => entry.StorageKey, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToList();
            _validator.ValidateAllAndThrow(snapshot);

            _entries.Clear();
            foreach (var entry in snapshot)
            {
                _entries[entry.StorageKey] = entry;
            }

            committed = true;
            _persistence.Save(snapshot);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            // If saving fails, the in-memory store still works
            _persistenceWarning = committed
                ? $"Could not save suppressions to disk: {ex.Message}. Accepted risks will last only for this session."
                : $"Could not save suppressions to disk: {ex.Message}. Invalid suppressions were not saved.";
        }
    }

    private void PersistCurrentState()
    {
        CommitCandidate(new Dictionary<string, SuppressionEntry>(_entries, StringComparer.OrdinalIgnoreCase));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
