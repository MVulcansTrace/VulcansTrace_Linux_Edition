namespace VulcansTrace.Linux.Agent.Messages;

/// <summary>
/// Defines storage and retrieval of pinned agent chat messages.
/// </summary>
public interface IPinnedMessageStore
{
    /// <summary>
    /// Pins a message. If a message with the same <see cref="PinnedMessage.MessageId"/> already exists, it is replaced.
    /// </summary>
    /// <param name="message">The message to pin.</param>
    void Pin(PinnedMessage message);

    /// <summary>
    /// Removes the pinned message with the specified identifier, if it exists.
    /// </summary>
    /// <param name="messageId">The stable fingerprint of the message to unpin.</param>
    void Unpin(string messageId);

    /// <summary>
    /// Checks whether a message with the specified identifier is pinned.
    /// </summary>
    /// <param name="messageId">The stable fingerprint to check.</param>
    /// <returns>True if pinned; otherwise, false.</returns>
    bool IsPinned(string messageId);

    /// <summary>
    /// Gets all pinned messages, ordered by most recently pinned first.
    /// </summary>
    IReadOnlyList<PinnedMessage> GetAll();

    /// <summary>
    /// Gets the latest persistence warning, if pins could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
