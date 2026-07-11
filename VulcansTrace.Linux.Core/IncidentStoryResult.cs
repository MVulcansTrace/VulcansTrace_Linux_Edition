namespace VulcansTrace.Linux.Core;

/// <summary>
/// Classifies a story beat by the kind of finding it narrates.
/// </summary>
public enum StoryBeatKind
{
    /// <summary>The beat narrates an event observed in logs (real event time).</summary>
    Event,

    /// <summary>The beat narrates a point-in-time configuration snapshot from an agent rule (scan time).</summary>
    Snapshot
}

/// <summary>
/// Represents a single beat in an incident attack narrative.
/// </summary>
public sealed record StoryBeat
{
    /// <summary>The timestamp of the event. <see cref="DateTime.MinValue"/> means the finding has no event timestamp.</summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>Gets whether the beat has a real event timestamp.</summary>
    public bool HasTimestamp { get; init; } = true;

    /// <summary>Human-readable timestamp label for display and markdown output.</summary>
    public required string TimestampLabel { get; init; }

    /// <summary>Human-readable sentence for this beat (e.g., "beaconing began.").</summary>
    public required string Narrative { get; init; }

    /// <summary>The finding category (e.g., Beaconing, LateralMovement).</summary>
    public required string Category { get; init; }

    /// <summary>The finding severity.</summary>
    public required Severity Severity { get; init; }

    /// <summary>Whether this beat narrates a log event or an agent-rule configuration snapshot.</summary>
    public StoryBeatKind Kind { get; init; } = StoryBeatKind.Event;
}

/// <summary>
/// The structured output of an incident story formatter, containing a flowing
/// attack narrative derived from findings and correlations.
/// </summary>
public sealed record IncidentStoryResult
{
    /// <summary>Ordered beats that make up the attack timeline.</summary>
    public required IReadOnlyList<StoryBeat> Beats { get; init; }

    /// <summary>Summary of the likely attack chain (e.g., "C2 → Lateral Movement → Privilege Escalation").</summary>
    public string LikelyChain { get; init; } = string.Empty;

    /// <summary>Whether a critical attack chain was detected.</summary>
    public bool HasCriticalChain { get; init; }

    /// <summary>Context-aware recommended responses.</summary>
    public IReadOnlyList<string> Recommendations { get; init; } = Array.Empty<string>();

    /// <summary>Raw markdown representation suitable for export.</summary>
    public string Markdown { get; init; } = string.Empty;
}
