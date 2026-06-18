using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// A single turn in the conversation, capturing the raw user input,
/// the resolved intent, and any extracted target reference.
/// </summary>
public sealed record DialogueTurn(
    string RawQuery,
    AgentIntent ResolvedIntent,
    string? TargetReference,
    DateTimeOffset TimestampUtc)
{
    /// <summary>
    /// Creates a turn stamped at the current UTC time.
    /// </summary>
    public static DialogueTurn Now(string rawQuery, AgentIntent resolvedIntent, string? targetReference)
        => new(rawQuery, resolvedIntent, targetReference, DateTimeOffset.UtcNow);
}
