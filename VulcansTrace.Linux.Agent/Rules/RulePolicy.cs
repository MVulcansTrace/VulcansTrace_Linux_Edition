using System.Collections.Immutable;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Describes per-role overrides for a single rule.
/// </summary>
public sealed record RulePolicy
{
    /// <summary>
    /// When <c>false</c>, the rule is skipped entirely for this role.
    /// </summary>
    public bool? Enabled { get; init; }

    /// <summary>
    /// Replaces the rule's default severity when it fails.
    /// </summary>
    public Severity? SeverityOverride { get; init; }

    /// <summary>
    /// When <c>true</c>, a failing result is treated as passed (looser).
    /// </summary>
    public bool? AutoPass { get; init; }

    /// <summary>
    /// Rule-specific key/value parameters for contextual rules.
    /// </summary>
    public ImmutableDictionary<string, string> Parameters { get; init; } = ImmutableDictionary<string, string>.Empty;
}
