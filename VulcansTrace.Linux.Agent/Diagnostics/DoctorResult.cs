using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Agent.Diagnostics;

/// <summary>
/// The result of a VulcansTrace Doctor diagnostic probe.
/// </summary>
public sealed record DoctorResult
{
    /// <summary>Individual data-source capabilities discovered by the scanners.</summary>
    public IReadOnlyList<DataSourceCapability> Capabilities { get; init; } = Array.Empty<DataSourceCapability>();

    /// <summary>Pre-formatted human-readable capability report.</summary>
    public string CapabilityReport { get; init; } = string.Empty;

    /// <summary>Whether every reported data source is fully available.</summary>
    public bool IsHealthy { get; init; }

    /// <summary>Number of sources that are permission-limited.</summary>
    public int PermissionLimitedCount { get; init; }

    /// <summary>Number of sources that are unavailable.</summary>
    public int UnavailableCount { get; init; }

    /// <summary>Number of sources that were not checked or have unknown availability.</summary>
    public int UnknownCount { get; init; }

    /// <summary>Scanner warnings emitted during the probe.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
