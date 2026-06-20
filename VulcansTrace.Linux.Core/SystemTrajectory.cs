namespace VulcansTrace.Linux.Core;

/// <summary>
/// Describes the net direction of the system across recent audits,
/// derived from per-rule trend data.
/// </summary>
public sealed record SystemTrajectory
{
    /// <summary>The overall direction of the system.</summary>
    public TrajectoryDirection Direction { get; init; }

    /// <summary>Number of rules currently trending improving.</summary>
    public int ImprovingCount { get; init; }

    /// <summary>Number of rules currently trending worsening.</summary>
    public int WorseningCount { get; init; }

    /// <summary>Number of rules currently stable.</summary>
    public int StableCount { get; init; }

    /// <summary>Weighted severity delta: positive favors improvement, negative favors worsening.</summary>
    public int WeightedDelta { get; init; }

    /// <summary>Example rule IDs that are improving, for citation.</summary>
    public IReadOnlyList<string> ImprovingRuleIds { get; init; } = Array.Empty<string>();

    /// <summary>Example rule IDs that are worsening, for citation.</summary>
    public IReadOnlyList<string> WorseningRuleIds { get; init; } = Array.Empty<string>();

    /// <summary>Example rule IDs that are stable, for citation.</summary>
    public IReadOnlyList<string> StableRuleIds { get; init; } = Array.Empty<string>();

    /// <summary>True when there is enough history to compute a meaningful trajectory.</summary>
    public bool HasEnoughHistory => (ImprovingCount + WorseningCount + StableCount) >= 2;
}

/// <summary>
/// The overall direction of a system trajectory.
/// </summary>
public enum TrajectoryDirection
{
    /// <summary>Not enough history to determine a direction.</summary>
    InsufficientHistory,

    /// <summary>The system is improving overall.</summary>
    Improving,

    /// <summary>The system is worsening overall.</summary>
    Worsening,

    /// <summary>The system is stable overall.</summary>
    Stable
}
