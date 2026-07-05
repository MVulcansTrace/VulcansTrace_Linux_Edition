using System.Collections.Concurrent;

namespace VulcansTrace.Linux.Agent.Findings;

/// <summary>
/// An in-memory pinned-finding store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryPinnedFindingStore : IPinnedFindingStore
{
    private readonly ConcurrentDictionary<string, PinnedFinding> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryPinnedFindingStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning shown when persistence is unavailable.</param>
    public InMemoryPinnedFindingStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public void Pin(PinnedFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentException.ThrowIfNullOrWhiteSpace(finding.Fingerprint);
        _entries[finding.Fingerprint] = finding;
    }

    /// <inheritdoc />
    public void Unpin(string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        _entries.TryRemove(fingerprint, out _);
    }

    /// <inheritdoc />
    public bool IsPinned(string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        return _entries.ContainsKey(fingerprint);
    }

    /// <inheritdoc />
    public IReadOnlyList<PinnedFinding> GetAll()
    {
        return _entries.Values
            .OrderByDescending(f => f.PinnedAtUtc)
            .ToList();
    }
}
