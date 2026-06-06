using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Event arguments raised when a scenario demo completes in the Avalonia UI.
/// </summary>
public sealed class DemoCompletedEventArgs : EventArgs
{
    /// <summary>The display name of the scenario that completed.</summary>
    public string ScenarioName { get; }

    /// <summary>Total delta findings produced during the demo.</summary>
    public int TotalFindings { get; }

    /// <summary>Findings produced by this demo run only.</summary>
    public IReadOnlyList<Finding> Findings { get; }

    /// <summary>Whether the demo stopped because the auto-stop timer fired.</summary>
    public bool WasAutoStop { get; }

    /// <summary>The configured duration of the demo.</summary>
    public TimeSpan Duration { get; }

    /// <summary>When the demo started.</summary>
    public DateTime StartTime { get; }

    /// <summary>When the demo ended.</summary>
    public DateTime EndTime { get; }

    public DemoCompletedEventArgs(
        string scenarioName,
        IReadOnlyList<Finding> findings,
        bool wasAutoStop,
        TimeSpan duration,
        DateTime startTime,
        DateTime endTime)
    {
        ScenarioName = scenarioName;
        Findings = findings;
        TotalFindings = findings.Count;
        WasAutoStop = wasAutoStop;
        Duration = duration;
        StartTime = startTime;
        EndTime = endTime;
    }
}
