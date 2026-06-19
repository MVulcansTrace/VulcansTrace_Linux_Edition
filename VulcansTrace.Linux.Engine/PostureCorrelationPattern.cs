using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// A declarative pattern that identifies a dangerous combination of two findings.
/// </summary>
public sealed record PostureCorrelationPattern
{
    /// <summary>Unique identifier for this pattern.</summary>
    public string PatternId { get; init; } = string.Empty;

    /// <summary>First rule ID. Supports wildcard suffix with '*'.</summary>
    public string RuleIdA { get; init; } = string.Empty;

    /// <summary>Second rule ID. Supports wildcard suffix with '*'.</summary>
    public string RuleIdB { get; init; } = string.Empty;

    /// <summary>Severity to assign to the combined condition.</summary>
    public Severity CombinedSeverity { get; init; }

    /// <summary>
    /// Narrative template explaining the combined risk.
    /// </summary>
    public string NarrativeTemplate { get; init; } = string.Empty;
}
