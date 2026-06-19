using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Persistent memory for a single rule across audits.
/// Tracks when it was first and last seen, its severity history,
/// remediation attempts, and derived trend.
/// </summary>
public sealed record RuleMemoryEntry
{
    /// <summary>The rule identifier (e.g., "FW-001").</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>The rule category (e.g., "Firewall").</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>UTC timestamp when this rule was first observed.</summary>
    public DateTime FirstSeenUtc { get; init; } = DateTime.UtcNow;

    /// <summary>UTC timestamp when this rule was most recently observed.</summary>
    public DateTime LastSeenUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Severity observations over time, ordered oldest to newest.</summary>
    public IReadOnlyList<RuleSeveritySnapshot> SeverityHistory { get; init; } = Array.Empty<RuleSeveritySnapshot>();

    /// <summary>UTC timestamp of the most recent remediation attempt, if any.</summary>
    public DateTime? LastRemediationAttemptUtc { get; init; }

    /// <summary>UTC timestamp when the rule was last verified as fixed, if ever.</summary>
    public DateTime? LastVerifiedFixedUtc { get; init; }

    /// <summary>Derived trend based on the most recent severity change.</summary>
    public RuleStatusTrend Trend { get; init; } = RuleStatusTrend.New;

    /// <summary>The most recent severity observed for this rule.</summary>
    public Severity LastSeverity { get; init; }

    /// <summary>The most recent target observed for this rule.</summary>
    public string LastTarget { get; init; } = string.Empty;
}
