using System.Globalization;

namespace VulcansTrace.Linux.Engine.LogDiff;

/// <summary>
/// Contains the complete diff between a baseline <see cref="Core.AnalysisResult"/> and an incident <see cref="Core.AnalysisResult"/>.
/// </summary>
public sealed record LogDiffResult
{
    /// <summary>Diffed connection-pattern events.</summary>
    public IReadOnlyList<DiffEvent> Events { get; init; } = Array.Empty<DiffEvent>();

    /// <summary>Diffed security findings.</summary>
    public IReadOnlyList<DiffFinding> Findings { get; init; } = Array.Empty<DiffFinding>();

    /// <summary>Start of the baseline time range.</summary>
    public DateTime BaselineTimeRangeStart { get; init; }

    /// <summary>End of the baseline time range.</summary>
    public DateTime BaselineTimeRangeEnd { get; init; }

    /// <summary>Start of the incident time range.</summary>
    public DateTime IncidentTimeRangeStart { get; init; }

    /// <summary>End of the incident time range.</summary>
    public DateTime IncidentTimeRangeEnd { get; init; }

    /// <summary>Optional label for the baseline source (e.g., file path) displayed in formatted output.</summary>
    public string BaselineLabel { get; init; } = "Baseline";

    /// <summary>Optional label for the incident source (e.g., file path) displayed in formatted output.</summary>
    public string IncidentLabel { get; init; } = "Incident";

    /// <summary>Number of Added connection patterns.</summary>
    public int AddedCount => Events.Count(e => e.State == LogDiffState.Added);

    /// <summary>Number of Removed connection patterns.</summary>
    public int RemovedCount => Events.Count(e => e.State == LogDiffState.Removed);

    /// <summary>Number of Changed connection patterns.</summary>
    public int ChangedCount => Events.Count(e => e.State == LogDiffState.Changed);

    /// <summary>Number of Unchanged connection patterns.</summary>
    public int UnchangedCount => Events.Count(e => e.State == LogDiffState.Unchanged);

    /// <summary>Number of Added findings.</summary>
    public int AddedFindingsCount => Findings.Count(f => f.State == LogDiffState.Added);

    /// <summary>Number of Removed findings.</summary>
    public int RemovedFindingsCount => Findings.Count(f => f.State == LogDiffState.Removed);

    /// <summary>Number of Changed findings.</summary>
    public int ChangedFindingsCount => Findings.Count(f => f.State == LogDiffState.Changed);

    /// <summary>Compact machine-readable summary.</summary>
    public string Summary =>
        $"{AddedCount} added, {RemovedCount} removed, {ChangedCount} changed, {UnchangedCount} unchanged patterns. " +
        $"{AddedFindingsCount} new, {RemovedFindingsCount} resolved, {ChangedFindingsCount} changed findings.";

    /// <summary>Deterministic human-readable narrative.</summary>
    public string Narrative
    {
        get
        {
            var parts = new List<string>();

            if (AddedCount > 0)
            {
                parts.Add($"{AddedCount} new traffic pattern{(AddedCount != 1 ? "s" : "")}");
            }

            if (RemovedCount > 0)
            {
                parts.Add($"{RemovedCount} disappeared traffic pattern{(RemovedCount != 1 ? "s" : "")}");
            }

            if (ChangedCount > 0)
            {
                parts.Add($"{ChangedCount} changed traffic pattern{(ChangedCount != 1 ? "s" : "")}");
            }

            if (AddedFindingsCount > 0)
            {
                parts.Add($"{AddedFindingsCount} new finding{(AddedFindingsCount != 1 ? "s" : "")}");
            }

            if (RemovedFindingsCount > 0)
            {
                parts.Add($"{RemovedFindingsCount} resolved finding{(RemovedFindingsCount != 1 ? "s" : "")}");
            }

            if (ChangedFindingsCount > 0)
            {
                parts.Add($"{ChangedFindingsCount} changed finding{(ChangedFindingsCount != 1 ? "s" : "")}");
            }

            if (parts.Count == 0)
            {
                return "No differences detected between the two logs.";
            }

            return string.Join(", ", parts) + ".";
        }
    }
}
