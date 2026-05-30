using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// Represents a user-designated "known good" configuration snapshot.
/// </summary>
public sealed record BaselineEntry
{
    /// <summary>Unique identifier for this baseline.</summary>
    public required string BaselineId { get; init; }

    /// <summary>User-friendly name for this baseline.</summary>
    public required string Name { get; init; }

    /// <summary>Optional description of what this baseline represents.</summary>
    public string? Description { get; init; }

    /// <summary>UTC timestamp when the baseline was created.</summary>
    public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;

    /// <summary>The audit intent/scope this baseline covers.</summary>
    public required AgentIntent Intent { get; init; }

    /// <summary>Total number of findings in the baseline snapshot.</summary>
    public int TotalFindings { get; init; }

    /// <summary>Number of critical findings in the baseline.</summary>
    public int CriticalCount { get; init; }

    /// <summary>Number of high findings in the baseline.</summary>
    public int HighCount { get; init; }

    /// <summary>Number of medium findings in the baseline.</summary>
    public int MediumCount { get; init; }

    /// <summary>Number of low findings in the baseline.</summary>
    public int LowCount { get; init; }

    /// <summary>Number of info findings in the baseline.</summary>
    public int InfoCount { get; init; }

    /// <summary>Whether this baseline is the active one for its intent.</summary>
    public bool IsActive { get; init; }

    /// <summary>Lightweight snapshot of findings for diff comparisons.</summary>
    public IReadOnlyList<Reports.AuditSnapshotFinding> SnapshotFindings { get; init; } = Array.Empty<Reports.AuditSnapshotFinding>();

    /// <summary>Original findings preserved for lossless display in ShowBaseline.</summary>
    public IReadOnlyList<VulcansTrace.Linux.Core.Finding> OriginalFindings { get; init; } = Array.Empty<VulcansTrace.Linux.Core.Finding>();
}
