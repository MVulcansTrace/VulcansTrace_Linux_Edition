namespace VulcansTrace.Linux.Core.Compliance;

/// <summary>
/// Score details for a single CIS control family.
/// </summary>
public sealed record ControlFamilyScore
{
    /// <summary>The numeric family identifier (e.g. "4").</summary>
    public string FamilyId { get; init; } = string.Empty;

    /// <summary>The human-readable family name (e.g. "Logging and Auditing").</summary>
    public string FamilyName { get; init; } = string.Empty;

    /// <summary>Total number of rules mapped to this family.</summary>
    public int TotalControls { get; init; }

    /// <summary>Number of rules that passed.</summary>
    public int PassedControls { get; init; }

    /// <summary>Number of rules that failed.</summary>
    public int FailedControls { get; init; }

    /// <summary>Number of rules that crashed during evaluation.</summary>
    public int CrashedControls { get; init; }

    /// <summary>Number of findings suppressed by user configuration.</summary>
    public int SuppressedControls { get; init; }

    /// <summary>Compliance percentage for this family (0–100).</summary>
    public double ScorePercentage { get; init; }

    /// <summary>Status: Pass, Warn, or Fail.</summary>
    public string Status { get; init; } = string.Empty;
}
