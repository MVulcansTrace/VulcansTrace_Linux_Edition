using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Confidence;

/// <summary>
/// Calculates the confidence level for a finding based on its evidence signals.
/// </summary>
public static class FindingConfidenceCalculator
{
    /// <summary>
    /// Calculates confidence from a collection of evidence signals.
    /// </summary>
    /// <param name="signals">Evidence signals associated with the finding.</param>
    /// <returns>The derived confidence level.</returns>
    public static DetectionConfidence Calculate(IReadOnlyList<EvidenceSignal> signals)
    {
        if (signals == null || signals.Count == 0)
        {
            return DetectionConfidence.Unknown;
        }

        bool hasThreatIntel = signals.Any(s =>
            string.Equals(s.Source, EvidenceSignal.ThreatIntelSource, StringComparison.OrdinalIgnoreCase));

        bool hasBehavior = signals.Any(s =>
            string.Equals(s.Source, EvidenceSignal.BehaviorSource, StringComparison.OrdinalIgnoreCase));

        if (hasThreatIntel && hasBehavior)
        {
            return DetectionConfidence.Confirmed;
        }

        return signals.Count switch
        {
            1 => DetectionConfidence.Low,
            2 => DetectionConfidence.Medium,
            _ => DetectionConfidence.High
        };
    }
}
