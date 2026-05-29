namespace VulcansTrace.Linux.Core;

/// <summary>
/// A lightweight summary of an active suppression for inclusion in evidence exports.
/// </summary>
public sealed record SuppressionSummary
{
    /// <summary>The rule identifier being suppressed.</summary>
    public required string RuleId { get; init; }

    /// <summary>The target resource being suppressed.</summary>
    public required string Target { get; init; }

    /// <summary>Optional reason for the suppression.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>UTC timestamp when the suppression was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC timestamp when the suppression expires, if any.</summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>UTC timestamp when the suppression should be reviewed, if any.</summary>
    public DateTime? ReviewDate { get; init; }
}
