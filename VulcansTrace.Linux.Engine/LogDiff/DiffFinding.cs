using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.LogDiff;

/// <summary>
/// Represents a <see cref="Finding"/> and how it changed between a baseline and an incident analysis.
/// </summary>
public sealed record DiffFinding
{
    /// <summary>The finding (from the incident side, or baseline for Removed).</summary>
    public required Finding Finding { get; init; }

    /// <summary>The diff state for this finding.</summary>
    public required LogDiffState State { get; init; }

    /// <summary>The previous severity (populated when <see cref="State"/> is <see cref="LogDiffState.Changed"/>).</summary>
    public Severity? OldSeverity { get; init; }

    /// <summary>The current severity (populated when <see cref="State"/> is <see cref="LogDiffState.Changed"/>).</summary>
    public Severity? NewSeverity { get; init; }
}
