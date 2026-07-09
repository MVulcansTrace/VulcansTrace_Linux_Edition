using System.Collections.Concurrent;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// An in-memory threat intel store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryThreatIntelStore : IThreatIntelStore
{
    private readonly ConcurrentDictionary<string, IocEntry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryThreatIntelStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning shown when persistence is unavailable.</param>
    public InMemoryThreatIntelStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public int Count => _entries.Count;

    /// <inheritdoc />
    public void Import(IEnumerable<IocEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        foreach (var entry in entries)
        {
            _entries[entry.StorageKey] = entry;
        }
    }

    /// <inheritdoc />
    public void Clear()
    {
        _entries.Clear();
    }

    /// <inheritdoc />
    public bool Remove(string storageKey)
    {
        ArgumentNullException.ThrowIfNull(storageKey);
        return _entries.TryRemove(storageKey, out _);
    }

    /// <inheritdoc />
    public int CountByType(IocType type)
    {
        var typeInt = (int)type;
        return _entries.Values.Count(e => (int)e.Type == typeInt);
    }

    /// <inheritdoc />
    public IReadOnlyList<IocEntry> GetByType(IocType type)
    {
        var typeInt = (int)type;
        return _entries.Values.Where(e => (int)e.Type == typeInt).ToList();
    }

    /// <inheritdoc />
    public IReadOnlyList<IocEntry> GetAll()
    {
        return _entries.Values.ToList();
    }
}
