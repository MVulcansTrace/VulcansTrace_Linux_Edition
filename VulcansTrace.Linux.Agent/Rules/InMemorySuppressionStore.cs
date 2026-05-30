using System.Collections.Concurrent;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// An in-memory suppression store that does not persist across process restarts.
/// </summary>
public sealed class InMemorySuppressionStore : ISuppressionStore
{
    private readonly ConcurrentDictionary<string, SuppressionEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemorySuppressionStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning shown when persistence is unavailable.</param>
    public InMemorySuppressionStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public void Add(SuppressionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entries[entry.StorageKey] = entry;
    }

    /// <inheritdoc />
    public void Remove(string ruleId, string target)
    {
        _entries.TryRemove($"{ruleId}|{target}", out _);
        var keysToRemove = _entries
            .Where(kvp => kvp.Value.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase)
                       && kvp.Value.Target.Equals(target, StringComparison.OrdinalIgnoreCase))
            .Select(kvp => kvp.Key)
            .ToList();
        foreach (var key in keysToRemove)
        {
            _entries.TryRemove(key, out _);
        }
    }

    /// <inheritdoc />
    public bool IsSuppressed(string ruleId, string target)
    {
        if (!_entries.TryGetValue($"{ruleId}|{target}", out var entry))
            return false;

        if (!string.IsNullOrEmpty(entry.Fingerprint))
            return false;

        if (entry.ExpiresAt.HasValue && entry.ExpiresAt.Value <= DateTime.UtcNow)
            return false;

        return true;
    }

    /// <inheritdoc />
    public bool IsSuppressed(string ruleId, string target, string fingerprint)
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

    /// <inheritdoc />
    public IReadOnlyList<SuppressionEntry> GetAll()
    {
        return _entries.Values
            .Where(e => !e.ExpiresAt.HasValue || e.ExpiresAt.Value > DateTime.UtcNow)
            .OrderByDescending(e => e.CreatedAt)
            .ToList();
    }

    /// <inheritdoc />
    public IReadOnlyList<SuppressionEntry> GetAllRaw()
    {
        return _entries.Values
            .OrderByDescending(e => e.CreatedAt)
            .ToList();
    }

    /// <inheritdoc />
    public int PruneExpired()
    {
        var cutoff = DateTime.UtcNow.AddDays(-SuppressionRetentionPolicy.ExpiredRetentionDays);
        var expiredKeys = _entries
            .Where(kvp => kvp.Value.ExpiresAt.HasValue && kvp.Value.ExpiresAt.Value <= cutoff)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expiredKeys)
        {
            _entries.TryRemove(key, out _);
        }

        return expiredKeys.Count;
    }
}
