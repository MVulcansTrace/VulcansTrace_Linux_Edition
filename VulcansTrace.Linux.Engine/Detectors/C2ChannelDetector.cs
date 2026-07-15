using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects potential Command & Control (C2) channel patterns by identifying periodic communication
/// between hosts that could indicate malware beaconing or C2 communication.
/// </summary>
/// <remarks>
/// This detector looks for regular intervals between connections from the same source to the same
/// destination, which is a common pattern in malware that periodically "phones home" to receive
/// commands or report status.
/// </remarks>
public sealed class C2ChannelDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Application Layer Protocol: Web Protocols", Tactic = "Command and Control", WhyItMatters = "C2 channels frequently use web protocols for covert command-and-control communication." },
        new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "Periodic communication patterns indicate malware phoning home via application-layer protocols." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableC2Detection || events.Count == 0)
        {
            return DetectionResult.Empty;
        }

        if (profile.C2ToleranceSeconds <= 0)
        {
            return DetectionResult.Empty;
        }

        var findings = new List<Core.Finding>();

        // Group events by connection key (source IP, dest IP, dest port, protocol).
        // Source port is intentionally ignored to catch beaconing with ephemeral ports.
        var minGroupSize = profile.C2MinGroupSize > 0 ? profile.C2MinGroupSize : 3;
        var byConnection = events
            .GroupBy(e => $"{e.SourceIP}-{e.DestinationIP}:{e.DestinationPort}-{e.Protocol}")
            .Where(g => g.Count() >= minGroupSize);

        foreach (var connGroup in byConnection)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var orderedEvents = connGroup.OrderBy(e => e.Timestamp).ToList();
            
            // Calculate time differences between consecutive events
            var timeDeltas = new List<double>();
            for (int i = 1; i < orderedEvents.Count; i++)
            {
                var delta = (orderedEvents[i].Timestamp - orderedEvents[i - 1].Timestamp).TotalSeconds;
                timeDeltas.Add(delta);
            }

            // Look for consistent time intervals (within tolerance)
            var tolerance = profile.C2ToleranceSeconds;
            var groupedDeltas = GroupSimilarDeltas(timeDeltas, tolerance, profile.C2MinOccurrences);

            var reportedIntervals = new HashSet<double>();
            foreach (var deltaGroup in groupedDeltas)
            {
                var interval = deltaGroup.Interval;
                
                // Skip intervals that are too short (likely legitimate traffic) or too long (not regular enough)
                if (interval < profile.C2MinIntervalSeconds || interval > profile.C2MaxIntervalSeconds)
                    continue;

                // Get the events that participate in this pattern using precomputed indices
                // instead of re-scanning all event pairs for each delta group.
                var patternEvents = new HashSet<UnifiedEvent>();
                foreach (var index in deltaGroup.Indices)
                {
                    patternEvents.Add(orderedEvents[index]);
                    patternEvents.Add(orderedEvents[index + 1]);
                }

                if (patternEvents.Count >= profile.C2MinPatternEvents)
                {
                    if (reportedIntervals.Add(interval))
                    {
                        var minTime = patternEvents.Min(e => e.Timestamp);
                        var maxTime = patternEvents.Max(e => e.Timestamp);
                        var connectionKey = $"{orderedEvents.First().SourceIP}-{orderedEvents.First().DestinationIP}:{orderedEvents.First().DestinationPort}-{orderedEvents.First().Protocol}";

                        var signals = new List<EvidenceSignal>
                        {
                            new EvidenceSignal
                            {
                                Name = "Periodic communication pattern",
                                Source = EvidenceSignal.BehaviorSource,
                                Explanation = $"{patternEvents.Count} events with ~{interval}s intervals"
                            },
                            new EvidenceSignal
                            {
                                Name = "Repeated destination tuple",
                                Source = EvidenceSignal.BehaviorSource,
                                Explanation = $"Consistent connections to {orderedEvents.First().DestinationIP}:{orderedEvents.First().DestinationPort}"
                            }
                        };

                        findings.Add(new Core.Finding
                        {
                            RuleId = EngineRuleIds.C2Channel,
                            Category = FindingCategories.C2Channel,
                            Severity = Core.Severity.High,
                            Confidence = FindingConfidenceCalculator.Calculate(signals),
                            SourceHost = orderedEvents.First().SourceIP,
                            Target = $"{orderedEvents.First().DestinationIP}:{orderedEvents.First().DestinationPort}",
                            TimeRangeStart = minTime,
                            TimeRangeEnd = maxTime,
                            ShortDescription = $"Potential C2 channel detected: {connectionKey}",
                            Details = $"Detected {patternEvents.Count} events with approximately {interval}s intervals (tolerance: \u00b1{tolerance}s). " +
                                      $"This pattern suggests periodic communication that may indicate a C2 channel.",
                            MitreTechniques = s_mitreTechniques,
                            EvidenceSignals = signals
                        });
                    }
                }
            }
        }

        return new DetectionResult(findings);
    }

    private static IReadOnlyList<DeltaGroup> GroupSimilarDeltas(IReadOnlyList<double> timeDeltas, double tolerance, int minOccurrences)
    {
        if (timeDeltas.Count == 0 || tolerance <= 0)
        {
            return Array.Empty<DeltaGroup>();
        }

        var sortedDeltas = timeDeltas
            .Select((delta, index) => new DeltaSample(delta, index))
            .OrderBy(sample => sample.Delta)
            .ToList();

        var groups = new List<DeltaGroup>();
        var maxSpan = tolerance * 2;

        for (var start = 0; start < sortedDeltas.Count;)
        {
            var samples = new List<DeltaSample> { sortedDeltas[start] };
            var end = start + 1;
            while (end < sortedDeltas.Count && sortedDeltas[end].Delta - sortedDeltas[start].Delta <= maxSpan)
            {
                samples.Add(sortedDeltas[end]);
                end++;
            }

            if (samples.Count >= minOccurrences)
            {
                groups.Add(new DeltaGroup(samples.Average(sample => sample.Delta), samples.Select(sample => sample.Index).ToList()));
                start = end;
            }
            else
            {
                start++;
            }
        }

        return groups;
    }

    private sealed record DeltaSample(double Delta, int Index);

    private sealed record DeltaGroup(double Interval, List<int> Indices);
}
