namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// The structured result of parsing a user query, including the inferred intent,
/// an optional reference to a specific finding or rule, and a frame of extracted entities.
/// </summary>
public sealed record AgentQuery(
    AgentIntent Intent,
    string? TargetReference = null,
    double Confidence = 1.0,
    IReadOnlyList<AgentIntent>? AlternativeIntents = null,
    bool IsAmbiguous = false,
    string? RawQuery = null)
{
    /// <summary>
    /// Structured entities extracted from the raw query (rule IDs, categories, severity filters, etc.).
    /// </summary>
    public QueryEntityFrame Entities { get; init; } = new();
}
