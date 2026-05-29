namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Predefined durations for suppression expiry.
/// </summary>
public enum SuppressionDuration
{
    /// <summary>Expires after 7 days.</summary>
    Days7,

    /// <summary>Expires after 30 days.</summary>
    Days30,

    /// <summary>Expires after 90 days.</summary>
    Days90,

    /// <summary>Never expires.</summary>
    Permanent
}

/// <summary>
/// Represents a user-accepted risk suppression for a specific rule and target.
/// </summary>
public sealed record SuppressionEntry
{
    /// <summary>The rule identifier being suppressed (e.g., "FW-001").</summary>
    public required string RuleId { get; init; }

    /// <summary>The target resource being suppressed (e.g., "SSH/22").</summary>
    public required string Target { get; init; }

    /// <summary>Optional reason for the suppression.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>UTC timestamp when the suppression was created.</summary>
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    /// <summary>UTC timestamp when the suppression expires, if any.</summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>UTC timestamp when the suppression should be reviewed, if any.</summary>
    public DateTime? ReviewDate { get; init; }

    /// <summary>
    /// Gets a composite key for matching this suppression against a finding.
    /// </summary>
    public string MatchKey => $"{RuleId}|{Target}";
}
