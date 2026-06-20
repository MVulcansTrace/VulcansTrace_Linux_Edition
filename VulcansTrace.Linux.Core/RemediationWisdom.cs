namespace VulcansTrace.Linux.Core;

/// <summary>
/// A deterministic insight derived from repeated remediation-recurrence cycles.
/// </summary>
public sealed record RemediationWisdom
{
    /// <summary>The rule identifier with recurring remediation cycles.</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>Number of completed remediation cycles (fixed and returned).</summary>
    public int CycleCount { get; init; }

    /// <summary>UTC timestamp of the most recent verified fix before the recurrence.</summary>
    public DateTime LastVerifiedFixedUtc { get; init; }

    /// <summary>Human-readable guidance for addressing the systemic cause.</summary>
    public string Guidance { get; init; } = string.Empty;
}
