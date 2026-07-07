namespace VulcansTrace.Linux.Agent.Messages;

/// <summary>
/// Represents an agent chat message that the user has pinned for later reference.
/// The <see cref="MessageId"/> is a unique instance identifier and acts as the primary key.
/// </summary>
public sealed record PinnedMessage
{
    /// <summary>
    /// Unique identifier of the pinned message instance. This is the primary key.
    /// </summary>
    public required string MessageId { get; init; }

    /// <summary>Whether the message originated from the user.</summary>
    public bool IsUser { get; init; }

    /// <summary>Primary message text.</summary>
    public required string Text { get; init; }

    /// <summary>Optional detail text for the message.</summary>
    public string Details { get; init; } = string.Empty;

    /// <summary>Finding category label, if any.</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>Severity label, if any.</summary>
    public string Severity { get; init; } = string.Empty;

    /// <summary>Whether the message is informational.</summary>
    public bool IsInfo { get; init; }

    /// <summary>Whether the message represents an error.</summary>
    public bool IsError { get; init; }

    /// <summary>Whether the message is prose that was streamed.</summary>
    public bool IsProse { get; init; }

    /// <summary>UTC timestamp of the original message.</summary>
    public DateTime TimestampUtc { get; init; }

    /// <summary>UTC timestamp when the message was pinned.</summary>
    public DateTime PinnedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Optional user note attached to the pinned message.</summary>
    public string Notes { get; init; } = string.Empty;
}
