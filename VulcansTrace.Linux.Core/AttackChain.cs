namespace VulcansTrace.Linux.Core;

/// <summary>
/// Describes an ordered attack chain: a sequence of findings that together
/// narrate a kill-chain path from reconnaissance to impact.
/// </summary>
public sealed record AttackChain
{
    /// <summary>Ordered links in the chain.</summary>
    public IReadOnlyList<AttackChainLink> Links { get; init; } = Array.Empty<AttackChainLink>();

    /// <summary>The highest severity in the chain.</summary>
    public Severity CombinedSeverity { get; init; }

    /// <summary>Human-readable narrative of the path.</summary>
    public string Narrative { get; init; } = string.Empty;

    /// <summary>Rule IDs cited by this chain.</summary>
    public IReadOnlyList<string> RuleIds { get; init; } = Array.Empty<string>();

    /// <summary>Source posture-correlation pattern IDs, if any.</summary>
    public IReadOnlyList<string> SourcePatternIds { get; init; } = Array.Empty<string>();
}

/// <summary>
/// A single stage in an attack chain.
/// </summary>
public sealed record AttackChainLink
{
    /// <summary>The rule identifier for this link.</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>The kill-chain stage enum value for sorting.</summary>
    public AttackChainStage Stage { get; init; }

    /// <summary>The finding identifier for this link.</summary>
    public Guid FindingId { get; init; }

    /// <summary>The kill-chain stage name.</summary>
    public string StageName { get; init; } = string.Empty;

    /// <summary>The severity of the finding at this link.</summary>
    public Severity Severity { get; init; }

    /// <summary>MITRE technique IDs cited at this link.</summary>
    public IReadOnlyList<string> MitreTechniqueIds { get; init; } = Array.Empty<string>();

    /// <summary>Rationale explaining why this rule belongs to this stage.</summary>
    public string Rationale { get; init; } = string.Empty;
}
