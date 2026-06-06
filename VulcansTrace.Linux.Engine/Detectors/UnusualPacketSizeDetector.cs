using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

public sealed class UnusualPacketSizeDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1001", TechniqueName = "Data Obfuscation", Tactic = "Command and Control", WhyItMatters = "Unusual packet sizes can be used to obfuscate data in covert channels." },
        new MitreTechnique { TechniqueId = "T1041", TechniqueName = "Exfiltration Over C2 Channel", Tactic = "Exfiltration", WhyItMatters = "Abnormal packet sizes may indicate data exfiltration over customized C2 protocols." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableUnusualPacketSize || events.Count == 0)
            return DetectionResult.Empty;

        var largeThreshold = profile.PacketSizeLargeThreshold > 0 ? profile.PacketSizeLargeThreshold : 3000;
        var smallThreshold = profile.PacketSizeSmallThreshold > 0 ? profile.PacketSizeSmallThreshold : 40;
        var minForAnalysis = profile.PacketSizeMinForAnalysis > 0 ? profile.PacketSizeMinForAnalysis : 10;
        var consistencyPercent = profile.PacketSizeConsistencyPercent > 0 ? profile.PacketSizeConsistencyPercent : 70;
        var minConsistentCount = profile.PacketSizeMinConsistentCount > 0 ? profile.PacketSizeMinConsistentCount : 10;
        var varianceRatio = profile.PacketSizeVarianceRatio > 0 ? profile.PacketSizeVarianceRatio : 0.5;
        var minAvgForVariance = profile.PacketSizeMinAvgForVariance > 0 ? profile.PacketSizeMinAvgForVariance : 100;

        var findings = new List<Core.Finding>();

        var sizeByTuple = new Dictionary<(string SrcIP, string DstIP, int DstPort, string Proto), List<UnifiedEvent>>();
        var largeGroups = new Dictionary<(string SrcIP, string DstIP), List<(int Size, DateTime Timestamp)>>();
        var smallGroups = new Dictionary<(string SrcIP, string DstIP), List<(int Size, DateTime Timestamp)>>();

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var lengthStr = evt.LinuxSpecific.GetValueOrDefault("Length", "");
            if (!int.TryParse(lengthStr, out var length))
                continue;

            if (length > largeThreshold)
            {
                var key = (evt.SourceIP, evt.DestinationIP);
                if (!largeGroups.TryGetValue(key, out var list))
                {
                    list = new List<(int, DateTime)>();
                    largeGroups[key] = list;
                }
                list.Add((length, evt.Timestamp));
                continue; // outlier — exclude from statistical analysis
            }

            if (length > 0 && length < smallThreshold)
            {
                var key = (evt.SourceIP, evt.DestinationIP);
                if (!smallGroups.TryGetValue(key, out var list))
                {
                    list = new List<(int, DateTime)>();
                    smallGroups[key] = list;
                }
                list.Add((length, evt.Timestamp));
                continue; // outlier — exclude from statistical analysis
            }

            // Only non-outlier packets feed into per-tuple statistical analysis
            var tupleKey = (evt.SourceIP, evt.DestinationIP, evt.DestinationPort, evt.Protocol);
            if (!sizeByTuple.TryGetValue(tupleKey, out var sizeList))
            {
                sizeList = new List<UnifiedEvent>();
                sizeByTuple[tupleKey] = sizeList;
            }
            sizeList.Add(evt);
        }

        foreach (var kvp in largeGroups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entries = kvp.Value;
            var minTime = entries.Min(e => e.Timestamp);
            var maxTime = entries.Max(e => e.Timestamp);
            var maxSize = entries.Max(e => e.Size);
            var minSize = entries.Min(e => e.Size);

            var largeSignals = new List<EvidenceSignal>
            {
                new EvidenceSignal
                {
                    Name = "Unusually large packets",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"{entries.Count} packet(s) from {kvp.Key.SrcIP} to {kvp.Key.DstIP} exceeded {largeThreshold} bytes (range: {minSize}-{maxSize} bytes)"
                }
            };
            findings.Add(new Core.Finding
            {
                Category = FindingCategories.UnusualPacketSize,
                Severity = Core.Severity.Medium,
                Confidence = FindingConfidenceCalculator.Calculate(largeSignals),
                SourceHost = kvp.Key.SrcIP,
                Target = kvp.Key.DstIP,
                TimeRangeStart = minTime,
                TimeRangeEnd = maxTime,
                ShortDescription = $"{entries.Count} unusually large packet(s) detected",
                Details = $"{entries.Count} packet(s) from {kvp.Key.SrcIP} to {kvp.Key.DstIP} exceeded {largeThreshold} bytes (range: {minSize}-{maxSize} bytes). May indicate data exfiltration, DoS attack, or protocol abuse.",
                MitreTechniques = s_mitreTechniques,
                EvidenceSignals = largeSignals
            });
        }

        foreach (var kvp in smallGroups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entries = kvp.Value;
            var minTime = entries.Min(e => e.Timestamp);
            var maxTime = entries.Max(e => e.Timestamp);

            var smallSignals = new List<EvidenceSignal>
            {
                new EvidenceSignal
                {
                    Name = "Unusually small packets",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"{entries.Count} packet(s) from {kvp.Key.SrcIP} to {kvp.Key.DstIP} were below {smallThreshold} bytes"
                }
            };
            findings.Add(new Core.Finding
            {
                Category = FindingCategories.UnusualPacketSize,
                Severity = Core.Severity.Low,
                Confidence = FindingConfidenceCalculator.Calculate(smallSignals),
                SourceHost = kvp.Key.SrcIP,
                Target = kvp.Key.DstIP,
                TimeRangeStart = minTime,
                TimeRangeEnd = maxTime,
                ShortDescription = $"{entries.Count} unusually small packet(s) detected",
                Details = $"{entries.Count} packet(s) from {kvp.Key.SrcIP} to {kvp.Key.DstIP} were below {smallThreshold} bytes. May indicate covert channel, reconnaissance, or protocol probing.",
                MitreTechniques = s_mitreTechniques,
                EvidenceSignals = smallSignals
            });
        }

        foreach (var kvp in sizeByTuple)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var tupleEvents = kvp.Value;
            if (tupleEvents.Count < minForAnalysis)
                continue;

            var packetSizes = tupleEvents
                .Select(e => int.TryParse(e.LinuxSpecific.GetValueOrDefault("Length", ""), out var len) ? len : 0)
                .Where(len => len > 0)
                .ToList();
            if (packetSizes.Count < minForAnalysis)
                continue;

            var avgSize = packetSizes.Average();
            var variance = packetSizes.Select(s => (s - avgSize) * (s - avgSize)).Average();
            var stdDev = Math.Sqrt(variance);

            var sizeGroups = packetSizes.GroupBy(s => s).OrderByDescending(g => g.Count()).ToList();
            var mostCommonSize = sizeGroups.First();
            var consistencyPct = (double)mostCommonSize.Count() / packetSizes.Count * 100;

            var minTime = tupleEvents.Min(e => e.Timestamp);
            var maxTime = tupleEvents.Max(e => e.Timestamp);
            var sourceHost = kvp.Key.SrcIP;
            var target = $"{kvp.Key.DstIP}:{kvp.Key.DstPort}";

            if (consistencyPct >= consistencyPercent && mostCommonSize.Count() >= minConsistentCount)
            {
                var consistentSignals = new List<EvidenceSignal>
                {
                    new EvidenceSignal
                    {
                        Name = "Highly consistent packet sizes",
                        Source = EvidenceSignal.BehaviorSource,
                        Explanation = $"{consistencyPct:F1}% of packets from {sourceHost} to {target} have the same size ({mostCommonSize.Key} bytes)"
                    }
                };
                findings.Add(new Core.Finding
                {
                    Category = FindingCategories.UnusualPacketSize,
                    Severity = Core.Severity.Medium,
                    Confidence = FindingConfidenceCalculator.Calculate(consistentSignals),
                    SourceHost = sourceHost,
                    Target = target,
                    TimeRangeStart = minTime,
                    TimeRangeEnd = maxTime,
                    ShortDescription = "Highly consistent packet sizes detected",
                    Details = $"{consistencyPct:F1}% of packets from {sourceHost} to {target} have the same size ({mostCommonSize.Key} bytes). This unusual consistency may indicate a covert channel using fixed-size packets for data exfiltration or command communication.",
                    MitreTechniques = s_mitreTechniques,
                    EvidenceSignals = consistentSignals
                });
            }

            if (stdDev > avgSize * varianceRatio && avgSize > minAvgForVariance)
            {
                var varianceSignals = new List<EvidenceSignal>
                {
                    new EvidenceSignal
                    {
                        Name = "High packet size variance",
                        Source = EvidenceSignal.BehaviorSource,
                        Explanation = $"Packet sizes from {sourceHost} to {target} show high variance (avg: {avgSize:F0} bytes, std dev: {stdDev:F0} bytes)"
                    }
                };
                findings.Add(new Core.Finding
                {
                    Category = FindingCategories.UnusualPacketSize,
                    Severity = Core.Severity.Low,
                    Confidence = FindingConfidenceCalculator.Calculate(varianceSignals),
                    SourceHost = sourceHost,
                    Target = target,
                    TimeRangeStart = minTime,
                    TimeRangeEnd = maxTime,
                    ShortDescription = "High packet size variance detected",
                    Details = $"Packet sizes from {sourceHost} to {target} show high variance (avg: {avgSize:F0} bytes, std dev: {stdDev:F0} bytes). This may indicate fragmented traffic, mixed protocols, or network anomalies.",
                    MitreTechniques = s_mitreTechniques,
                    EvidenceSignals = varianceSignals
                });
            }
        }

        return new DetectionResult(findings);
    }
}
