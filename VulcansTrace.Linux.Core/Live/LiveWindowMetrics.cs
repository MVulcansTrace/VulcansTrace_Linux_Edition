namespace VulcansTrace.Linux.Core.Live;

/// <summary>
/// Metrics describing the current live stream window state.
/// </summary>
public sealed record LiveWindowMetrics
{
    /// <summary>Number of events currently in the rolling window.</summary>
    public int EventCount { get; init; }

    /// <summary>Total bytes captured (packet payload lengths) in the current window.</summary>
    public long TotalBytes { get; init; }

    /// <summary>Duration of the window from oldest to newest event.</summary>
    public TimeSpan WindowDuration { get; init; }

    /// <summary>Number of unique source IP addresses in the window.</summary>
    public int UniqueSourceCount { get; init; }

    /// <summary>Number of unique destination IP addresses in the window.</summary>
    public int UniqueDestinationCount { get; init; }

    /// <summary>Events per second averaged over the window.</summary>
    public double EventsPerSecond { get; init; }

    /// <summary>Timestamp when the metrics were computed.</summary>
    public DateTime ComputedAt { get; init; } = DateTime.UtcNow;
}
