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
        _entries[entry.MatchKey] = entry;
    }

    /// <inheritdoc />
    public void Remove(string ruleId, string target)
    {
        _entries.TryRemove($"{ruleId}|{target}", out _);
    }

    /// <inheritdoc />
    public bool IsSuppressed(string ruleId, string target)
    {
        return _entries.ContainsKey($"{ruleId}|{target}");
    }

    /// <inheritdoc />
    public IReadOnlyList<SuppressionEntry> GetAll()
    {
        return _entries.Values.OrderByDescending(e => e.CreatedAt).ToList();
    }
}
