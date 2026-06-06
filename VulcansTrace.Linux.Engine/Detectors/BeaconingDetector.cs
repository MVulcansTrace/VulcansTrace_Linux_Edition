using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Net;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects beaconing behavior indicating command-and-control (C2) communication.
/// </summary>
/// <remarks>
/// Beaconing is identified by regular, periodic connections from a host to the same
/// external destination. The detector analyzes connection intervals for low variance,
/// which is characteristic of automated malware callbacks to C2 servers.
/// </remarks>
public sealed class BeaconingDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Application Layer Protocol: Web Protocols", Tactic = "Command and Control", WhyItMatters = "Beaconing to external destinations is a hallmark of C2 communication over web protocols." },
        new MitreTechnique { TechniqueId = "T1001", TechniqueName = "Data Obfuscation", Tactic = "Command and Control", WhyItMatters = "Regular beaconing intervals may be used to obfuscate malicious traffic within normal network patterns." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableBeaconing || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();

        var byTuple = events
            .Where(e => IpClassification.IsExternal(e.DestinationIP))
            .GroupBy(e => (e.SourceIP, e.DestinationIP, e.DestinationPort));

        foreach (var group in byTuple)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            if (profile.BeaconMaxSamplesPerTuple > 0 && ordered.Count > profile.BeaconMaxSamplesPerTuple)
            {
                ordered = ordered.Skip(ordered.Count - profile.BeaconMaxSamplesPerTuple).ToList();
            }

            if (ordered.Count < profile.BeaconMinEvents)
                continue;

            var durationSeconds = (ordered[^1].Timestamp - ordered[0].Timestamp).TotalSeconds;
            if (durationSeconds < profile.BeaconMinDurationSeconds)
                continue;

            var intervals = new List<double>();
            for (int i = 1; i < ordered.Count; i++)
            {
                intervals.Add((ordered[i].Timestamp - ordered[i - 1].Timestamp).TotalSeconds);
            }

            if (intervals.Count == 0)
                continue;

            intervals.Sort();
            var trimmed = TrimIntervals(intervals, profile.BeaconTrimPercent);

            var mean = trimmed.Average();
            var variance = trimmed.Select(v => (v - mean) * (v - mean)).Average();
            var stdDev = Math.Sqrt(variance);

            if (mean < profile.BeaconMinIntervalSeconds || mean > profile.BeaconMaxIntervalSeconds)
                continue;

            if (stdDev > profile.BeaconStdDevThreshold)
                continue;

            var first = ordered.First();
            var last = ordered.Last();

            var signals = new List<EvidenceSignal>
            {
                new EvidenceSignal
                {
                    Name = "Periodic outbound traffic",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"Average interval ~{mean:F1}s over {ordered.Count} events"
                },
                new EvidenceSignal
                {
                    Name = "Low interval variance",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"Standard deviation ~{stdDev:F1}s below threshold"
                },
                new EvidenceSignal
                {
                    Name = "External destination persistence",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"Repeated connections to {group.Key.DestinationIP}:{group.Key.DestinationPort}"
                }
            };

            findings.Add(new Core.Finding
            {
                Category = FindingCategories.Beaconing,
                Severity = Core.Severity.Medium,
                Confidence = FindingConfidenceCalculator.Calculate(signals),
                SourceHost = group.Key.SourceIP,
                Target = $"{group.Key.DestinationIP}:{group.Key.DestinationPort}",
                TimeRangeStart = first.Timestamp,
                TimeRangeEnd = last.Timestamp,
                ShortDescription = $"Regular beaconing from {group.Key.SourceIP}",
                Details = $"Average interval ~{mean:F1}s, std dev ~{stdDev:F1}s over {ordered.Count} events.",
                MitreTechniques = s_mitreTechniques,
                EvidenceSignals = signals
            });
        }

        return new DetectionResult(findings);
    }

    private static IReadOnlyList<double> TrimIntervals(IReadOnlyList<double> sortedIntervals, double trimPercent)
    {
        if (sortedIntervals.Count <= 2 || trimPercent <= 0)
            return sortedIntervals;

        var trimCount = (int)Math.Ceiling(sortedIntervals.Count * trimPercent);
        if (trimCount == 0)
            return sortedIntervals;

        var start = trimCount;
        var length = sortedIntervals.Count - (2 * trimCount);
        if (length < 2)
            return sortedIntervals;

        return sortedIntervals.Skip(start).Take(length).ToList();
    }
}
