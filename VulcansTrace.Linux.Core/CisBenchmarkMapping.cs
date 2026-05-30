namespace VulcansTrace.Linux.Core;

/// <summary>
/// Maps a security finding to a CIS Benchmark control, explaining the compliance context.
/// </summary>
public sealed record CisBenchmarkMapping
{
    /// <summary>The CIS Control identifier (e.g., "CIS 4.5").</summary>
    public required string ControlId { get; init; }

    /// <summary>The human-readable name of the CIS control.</summary>
    public required string ControlName { get; init; }

    /// <summary>Why this finding matters in a compliance / audit context.</summary>
    public required string WhyItMatters { get; init; }

    /// <summary>Optional: specific CIS Linux Benchmark reference (e.g. "CIS Ubuntu 24.04 LTS 5.2.7").</summary>
    public string? BenchmarkReference { get; init; }
}
