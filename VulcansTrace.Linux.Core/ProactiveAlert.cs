namespace VulcansTrace.Linux.Core;

/// <summary>
/// Describes a finding that has returned after a previous verified fix,
/// surfaced proactively in the narrative.
/// </summary>
public sealed record ProactiveAlert
{
    /// <summary>The rule identifier that has returned.</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>UTC timestamp when the rule was last verified as fixed.</summary>
    public DateTime LastVerifiedFixedUtc { get; init; }

    /// <summary>Number of days between the last verified fix and the current audit.</summary>
    public int DaysSinceVerifiedFixed { get; init; }

    /// <summary>The current severity of the returned finding.</summary>
    public Severity CurrentSeverity { get; init; }

    /// <summary>Category-specific guidance for investigating why the finding returned.</summary>
    public string Guidance { get; init; } = string.Empty;
}
