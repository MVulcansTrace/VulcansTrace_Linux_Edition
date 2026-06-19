using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Describes a cross-category posture correlation: two findings that together
/// create a higher-risk condition than either finding alone.
/// </summary>
public sealed record PostureCorrelation
{
    /// <summary>Unique identifier for this correlation pattern instance.</summary>
    public string PatternId { get; init; } = string.Empty;

    /// <summary>First rule ID in the correlated pair.</summary>
    public string RuleIdA { get; init; } = string.Empty;

    /// <summary>Second rule ID in the correlated pair.</summary>
    public string RuleIdB { get; init; } = string.Empty;

    /// <summary>Human-readable narrative explaining why the pair is worse together.</summary>
    public string Narrative { get; init; } = string.Empty;

    /// <summary>The combined severity of the pair.</summary>
    public Severity CombinedSeverity { get; init; }

    /// <summary>Rule IDs of the findings that matched this pattern.</summary>
    public IReadOnlyList<string> MatchedFindingRuleIds { get; init; } = Array.Empty<string>();

    /// <summary>The IDs of the matched findings, for traceability.</summary>
    public IReadOnlyList<Guid> FindingIds { get; init; } = Array.Empty<Guid>();
}
