using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// A single severity observation for a rule at a point in time.
/// </summary>
public sealed record RuleSeveritySnapshot
{
    /// <summary>UTC timestamp when the observation was recorded.</summary>
    public DateTime UtcTimestamp { get; init; } = DateTime.UtcNow;

    /// <summary>The severity reported for the rule at this observation.</summary>
    public Severity Severity { get; init; }

    /// <summary>The finding target, if available, to distinguish multiple instances of the same rule.</summary>
    public string Target { get; init; } = string.Empty;
}
