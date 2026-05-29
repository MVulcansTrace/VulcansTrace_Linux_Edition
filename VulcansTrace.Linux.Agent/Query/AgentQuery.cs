namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// The structured result of parsing a user query, including the inferred intent
/// and an optional reference to a specific finding or rule.
/// </summary>
public sealed record AgentQuery(AgentIntent Intent, string? TargetReference = null);
