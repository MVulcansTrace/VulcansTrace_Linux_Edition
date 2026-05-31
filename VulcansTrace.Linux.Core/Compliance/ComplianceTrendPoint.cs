namespace VulcansTrace.Linux.Core.Compliance;

/// <summary>
/// A single point in the compliance trend over time.
/// </summary>
public sealed record ComplianceTrendPoint
{
    /// <summary>UTC timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Overall compliance score at this point (0–100).</summary>
    public double OverallScore { get; init; }

    /// <summary>Optional per-family scores at this point.</summary>
    public IReadOnlyDictionary<string, double>? FamilyScores { get; init; }
}
