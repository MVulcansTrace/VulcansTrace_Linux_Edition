using System;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Describes the progress of a long-running agent audit so the UI can show
/// a determinate progress bar and a human-readable phase label.
/// </summary>
public sealed record AgentAuditProgress
{
    /// <summary>Human-readable phase name, e.g. "Scanning system".</summary>
    public required string Phase { get; init; }

    /// <summary>Optional detail, e.g. the scanners or rules currently active.</summary>
    public string? Detail { get; init; }

    /// <summary>Zero-based index of the current phase.</summary>
    public int StepIndex { get; init; }

    /// <summary>Total number of phases in the audit pipeline.</summary>
    public int TotalSteps { get; init; }

    /// <summary>
    /// Percentage complete based on <see cref="StepIndex"/> and <see cref="TotalSteps"/>.
    /// Returns 0 when <see cref="TotalSteps"/> is 0.
    /// </summary>
    public double PercentComplete => TotalSteps > 0 ? (StepIndex + 1) * 100.0 / TotalSteps : 0;

    /// <summary>
    /// True when the phase duration is unknown and the UI should show an indeterminate
    /// progress bar instead of a determinate one.
    /// </summary>
    public bool IsIndeterminate { get; init; }

    /// <summary>
    /// Creates a compact display string suitable for the UI status label.
    /// </summary>
    public string FormatMessage()
    {
        if (IsIndeterminate)
        {
            return string.IsNullOrWhiteSpace(Detail)
                ? Phase
                : $"{Phase} — {Detail}";
        }

        var percent = Math.Clamp((int)PercentComplete, 0, 100);
        return string.IsNullOrWhiteSpace(Detail)
            ? $"{Phase} ({percent}%)"
            : $"{Phase} — {Detail} ({percent}%)";
    }
}
