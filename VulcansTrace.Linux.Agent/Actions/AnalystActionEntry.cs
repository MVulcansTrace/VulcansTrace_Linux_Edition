namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// A single durable, queryable record of an operator/analyst action.
/// </summary>
public sealed record AnalystActionEntry
{
    /// <summary>Unique identifier for this log entry.</summary>
    public required string Id { get; init; }

    /// <summary>UTC timestamp when the action was recorded.</summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>The actor that performed the action, e.g. "cli" or "avalonia".</summary>
    public required string Actor { get; init; }

    /// <summary>The action type, usually one of the constants in <see cref="AnalystActionType"/>.</summary>
    public required string ActionType { get; init; }

    /// <summary>Optional target of the action, e.g. a rule id or file path.</summary>
    public string? Target { get; init; }

    /// <summary>Optional human-readable details.</summary>
    public string? Details { get; init; }

    /// <summary>Optional severity label.</summary>
    public string? Severity { get; init; }
}
