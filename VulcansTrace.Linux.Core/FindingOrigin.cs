namespace VulcansTrace.Linux.Core;

/// <summary>
/// Identifies which subsystem produced a <see cref="Finding"/>.
/// </summary>
public enum FindingOrigin
{
    /// <summary>Produced by log-analysis detectors (event-driven; participates in temporal attack chains).</summary>
    Detector,

    /// <summary>Produced by Security Agent posture rules and audit-derived views (point-in-time system state).</summary>
    AgentRule,
}
