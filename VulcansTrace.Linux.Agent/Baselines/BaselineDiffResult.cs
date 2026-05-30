using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Baselines;

/// <summary>
/// Represents the drift between a saved baseline and a live audit.
/// </summary>
public sealed record BaselineDiffResult
{
    /// <summary>The baseline being compared against.</summary>
    public required BaselineEntry Baseline { get; init; }

    /// <summary>The computed diff between baseline and live audit.</summary>
    public required AuditDiff Diff { get; init; }

    /// <summary>Whether any drift was detected (new or worsened findings).</summary>
    public bool HasDrift => Diff.NewFindings.Count > 0 || Diff.WorsenedFindings.Count > 0;

    /// <summary>Human-readable drift narrative.</summary>
    public string Narrative
    {
        get
        {
            if (!HasDrift)
            {
                return $"No drift detected against baseline '{Baseline.Name}'. Configuration matches baseline.";
            }

            return $"Drift detected against baseline '{Baseline.Name}': {Diff.Narrative}";
        }
    }
}
