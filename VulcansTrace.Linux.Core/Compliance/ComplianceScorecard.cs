namespace VulcansTrace.Linux.Core.Compliance;

/// <summary>
/// A formal CIS compliance scorecard summarizing pass/fail/warn status per control family,
/// an overall percentage score, and trend over time.
/// </summary>
public sealed record ComplianceScorecard
{
    /// <summary>Overall compliance score from 0 to 100.</summary>
    public double OverallScore { get; init; }

    /// <summary>Overall status: Pass, Warn, or Fail.</summary>
    public string SummaryStatus { get; init; } = string.Empty;

    /// <summary>Score breakdown per CIS control family.</summary>
    public IReadOnlyList<ControlFamilyScore> FamilyScores { get; init; } = Array.Empty<ControlFamilyScore>();

    /// <summary>Trend points showing overall score over previous audits.</summary>
    public IReadOnlyList<ComplianceTrendPoint> Trend { get; init; } = Array.Empty<ComplianceTrendPoint>();

    /// <summary>UTC timestamp when the scorecard was generated.</summary>
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;

    /// <summary>Minimum overall score (inclusive) for a Pass status.</summary>
    public const double PassThreshold = 90.0;

    /// <summary>Minimum overall score (inclusive) for a Warn status; below this is Fail.</summary>
    public const double WarnThreshold = 80.0;
}
