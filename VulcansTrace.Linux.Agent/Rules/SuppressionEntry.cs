namespace VulcansTrace.Linux.Agent.Rules;

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

    /// <summary>
    /// Gets a composite key for matching this suppression against a finding.
    /// </summary>
    public string MatchKey => $"{RuleId}|{Target}";
}
