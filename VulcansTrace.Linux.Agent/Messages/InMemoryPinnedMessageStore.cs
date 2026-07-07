using System.Collections.Concurrent;

namespace VulcansTrace.Linux.Agent.Messages;

/// <summary>
/// An in-memory pinned-message store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryPinnedMessageStore : IPinnedMessageStore
{
    private readonly ConcurrentDictionary<string, PinnedMessage> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryPinnedMessageStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning shown when persistence is unavailable.</param>
    public InMemoryPinnedMessageStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public void Pin(PinnedMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrWhiteSpace(message.MessageId);
        _entries[message.MessageId] = message;
    }

    /// <inheritdoc />
    public void Unpin(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        _entries.TryRemove(messageId, out _);
    }

    /// <inheritdoc />
    public bool IsPinned(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        return _entries.ContainsKey(messageId);
    }

    /// <inheritdoc />
    public IReadOnlyList<PinnedMessage> GetAll()
    {
        return _entries.Values
            .OrderByDescending(m => m.PinnedAtUtc)
            .ToList();
    }
}
