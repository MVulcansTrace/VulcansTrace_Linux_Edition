namespace VulcansTrace.Linux.Core.Live;

/// <summary>
/// Result of a single live stream analysis window.
/// Contains the full analysis output plus delta metrics relative to the previous window.
/// </summary>
public sealed record LiveAnalysisResult
{
    /// <summary>
    /// The complete <see cref="AnalysisResult"/> produced from the current window.
    /// </summary>
    public required AnalysisResult Analysis { get; init; }

    /// <summary>
    /// Findings that are new in this window compared to the previous analysis.
    /// Deduplicated by fingerprint.
    /// </summary>
    public IReadOnlyList<Finding> DeltaFindings { get; init; } = Array.Empty<Finding>();

    /// <summary>
    /// Metrics for the window that produced this result.
    /// </summary>
    public LiveWindowMetrics WindowMetrics { get; init; } = new();

    /// <summary>
    /// Number of times the detector pipeline has run so far in this live session.
    /// </summary>
    public int AnalysisRunCount { get; init; }

    /// <summary>
    /// The event source that produced the events for this window.
    /// </summary>
    public string SourceName { get; init; } = string.Empty;

    /// <summary>
    /// Timestamp when this live analysis result was produced.
    /// </summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
}
