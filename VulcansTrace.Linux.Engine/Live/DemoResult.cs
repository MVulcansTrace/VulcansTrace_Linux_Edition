using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// The completed artifacts from a demo run.
/// </summary>
public sealed record DemoResult
{
    /// <summary>The aggregated analysis result containing all findings from the demo.</summary>
    public required AnalysisResult AnalysisResult { get; init; }

    /// <summary>Trace map correlation of demo findings.</summary>
    public required TraceMapResult TraceMap { get; init; }

    /// <summary>A synthetic log description used for evidence export.</summary>
    public required string RawLogDescription { get; init; }

    /// <summary>The scenario that was run.</summary>
    public required DemoScenario Scenario { get; init; }

    /// <summary>The configured duration of the demo.</summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>The analysis intensity used.</summary>
    public required IntensityLevel Intensity { get; init; }

    /// <summary>When the demo started.</summary>
    public required DateTime StartTime { get; init; }

    /// <summary>When the demo ended.</summary>
    public required DateTime EndTime { get; init; }
}
