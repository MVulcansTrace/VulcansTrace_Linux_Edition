using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Suggestions;

/// <summary>
/// A single contextual follow-up suggestion that the user can click or speak.
/// </summary>
public sealed record SuggestedFollowUp
{
    /// <summary>User-facing label shown on the suggestion chip.</summary>
    public required string Label { get; init; }

    /// <summary>The natural-language query to execute when the suggestion is chosen.</summary>
    public required string Query { get; init; }

    /// <summary>The intent this suggestion maps to.</summary>
    public AgentIntent Intent { get; init; }
}
