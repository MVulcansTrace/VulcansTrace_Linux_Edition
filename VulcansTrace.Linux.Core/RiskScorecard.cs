namespace VulcansTrace.Linux.Core;

/// <summary>
/// A risk scorecard that aggregates all findings into a single numeric score (0–100)
/// and letter grade (A–F), weighted by severity and CIS control importance.
/// </summary>
public sealed record RiskScorecard
{
    /// <summary>Overall risk score from 0 to 100, where 100 means no risk.</summary>
    public double NumericScore { get; init; }

    /// <summary>Letter grade derived from the numeric score (A–F).</summary>
    public string LetterGrade { get; init; } = string.Empty;

    /// <summary>Human-readable risk summary (e.g. Low, Moderate, High, Severe).</summary>
    public string SummaryStatus { get; init; } = string.Empty;

    /// <summary>Total number of findings included in the score.</summary>
    public int TotalFindings { get; init; }

    /// <summary>Score breakdown per finding category.</summary>
    public IReadOnlyList<CategoryRisk> ByCategory { get; init; } = Array.Empty<CategoryRisk>();

    /// <summary>UTC timestamp when the scorecard was generated.</summary>
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;

    /// <summary>Minimum score (inclusive) for an A grade.</summary>
    public const double AThreshold = 90.0;

    /// <summary>Minimum score (inclusive) for a B grade.</summary>
    public const double BThreshold = 80.0;

    /// <summary>Minimum score (inclusive) for a C grade.</summary>
    public const double CThreshold = 70.0;

    /// <summary>Minimum score (inclusive) for a D grade.</summary>
    public const double DThreshold = 60.0;
}
