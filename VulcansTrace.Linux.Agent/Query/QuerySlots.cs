namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Modifier slots extracted from a raw query, orthogonal to the primary <see cref="AgentIntent"/>.
/// Carried on <see cref="AgentQuery"/> so routing decisions (reuse-vs-scan, terse-vs-full) are based
/// on structured data rather than re-scanning the raw string at each consumer.
/// </summary>
public sealed record QuerySlots
{
    /// <summary>Default slots: <see cref="Query.Freshness.Auto"/>, <see cref="Query.QueryVerbosity.Normal"/>, no category or finding reference.</summary>
    public static QuerySlots Default { get; } = new();

    /// <summary>Reuse-vs-scan preference for audit questions.</summary>
    public Freshness Freshness { get; init; } = Freshness.Auto;

    /// <summary>Output-length preference.</summary>
    public QueryVerbosity Verbosity { get; init; } = QueryVerbosity.Normal;

    /// <summary>Canonical audit category when the query targets one (from <see cref="IntentCategoryMap"/>); null for full audits and non-audit intents.</summary>
    public string? Category { get; init; }

    /// <summary>A referenced rule/finding ID (e.g. FW-001) when present in the query; otherwise null.</summary>
    public string? FindingReference { get; init; }
}
