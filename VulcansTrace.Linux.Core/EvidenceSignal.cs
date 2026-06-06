namespace VulcansTrace.Linux.Core;

/// <summary>
/// Represents a single piece of evidence that contributes to a finding's confidence score.
/// </summary>
public sealed record EvidenceSignal
{
    public const string ThreatIntelSource = "ThreatIntel";
    public const string BehaviorSource = "Behavior";

    /// <summary>Name of the signal (e.g., "Periodic outbound traffic").</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Source or detector that produced the signal (e.g., "ThreatIntel", "Behavior").</summary>
    public string Source { get; init; } = string.Empty;

    /// <summary>Human-readable explanation of why this signal matters.</summary>
    public string Explanation { get; init; } = string.Empty;
}
