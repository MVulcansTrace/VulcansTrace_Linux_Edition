using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// A structured frame of entities extracted from a user query.
/// Used by the dialogue manager to resolve references and disambiguate intent.
/// All extraction is deterministic; no external NLP dependencies are used.
/// </summary>
public sealed record QueryEntityFrame
{
    /// <summary>Rule IDs explicitly referenced in the query (e.g., "FW-001").</summary>
    public IReadOnlyList<string> RuleIds { get; init; } = Array.Empty<string>();

    /// <summary>Categories explicitly referenced in the query (e.g., "firewall", "ssh").</summary>
    public IReadOnlyList<string> Categories { get; init; } = Array.Empty<string>();

    /// <summary>Remediation session ID explicitly referenced in the query.</summary>
    public string? SessionId { get; init; }

    /// <summary>Severity filter explicitly referenced in the query.</summary>
    public Severity? SeverityFilter { get; init; }

    /// <summary>Time window referenced in the query, if any.</summary>
    public TimeSpan? TimeWindow { get; init; }

    /// <summary>Absolute cutoff time referenced in the query (e.g., "since baseline").</summary>
    public DateTime? SinceUtc { get; init; }

    /// <summary>Remediation verb extracted from the query, if any.</summary>
    public AgentIntent? RemediationVerb { get; init; }

    /// <summary>Baseline name referenced in the query, if any.</summary>
    public string? BaselineName { get; init; }

    /// <summary>The raw query tokens, normalized and lower-case, for fallback matching.</summary>
    public IReadOnlyList<string> Tokens { get; init; } = Array.Empty<string>();

    /// <summary>Whether the query contains ordinal references like "the third one".</summary>
    public int? OrdinalReference { get; init; }

    /// <summary>Whether any entities were extracted.</summary>
    public bool HasEntities =>
        RuleIds.Count > 0
        || Categories.Count > 0
        || !string.IsNullOrWhiteSpace(SessionId)
        || SeverityFilter.HasValue
        || TimeWindow.HasValue
        || SinceUtc.HasValue
        || RemediationVerb.HasValue
        || !string.IsNullOrWhiteSpace(BaselineName)
        || OrdinalReference.HasValue;
}
