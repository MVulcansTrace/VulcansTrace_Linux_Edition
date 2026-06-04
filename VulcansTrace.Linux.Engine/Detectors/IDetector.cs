using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Defines the contract for threat detection algorithms.
/// </summary>
/// <remarks>
/// Implementations analyze UnifiedEvent entries according to a specific detection strategy (e.g., port scans, beaconing).
/// </remarks>
public interface IDetector
{
    /// <summary>MITRE ATT&CK techniques this detector maps to (may be empty).</summary>
    IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

    /// <summary>
    /// Analyzes UnifiedEvent entries to detect security threats.
    /// Implementations may return multiple findings per source IP when
    /// separate incidents are detected within the event stream.
    /// </summary>
    /// <param name="events">The unified event entries to analyze.</param>
    /// <param name="profile">The analysis profile containing detection thresholds.</param>
    /// <param name="cancellationToken">Token to cancel the detection operation.</param>
    /// <returns>A <see cref="DetectionResult"/> containing findings and any warnings produced during analysis.</returns>
    DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken);
}
