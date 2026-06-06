using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Net;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

public sealed class NoveltyDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "Novel destinations may indicate C2 infrastructure testing or domain generation algorithm usage." },
        new MitreTechnique { TechniqueId = "T1041", TechniqueName = "Exfiltration Over C2 Channel", Tactic = "Exfiltration", WhyItMatters = "Rare external destinations can signal data exfiltration over newly established C2 channels." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableNovelty || events.Count == 0)
            return DetectionResult.Empty;

        var externalEntries = events.Where(e => IpClassification.IsExternal(e.DestinationIP)).ToList();
        if (externalEntries.Count == 0)
            return DetectionResult.Empty;

        var counts = externalEntries
            .GroupBy(e => (e.DestinationIP, e.DestinationPort))
            .ToDictionary(g => g.Key, g => g.Count());

        var bySource = new Dictionary<string, List<(string DstIP, int DstPort, DateTime Timestamp)>>();

        var maxOccurrences = profile.NoveltyMaxGlobalOccurrences > 0 ? profile.NoveltyMaxGlobalOccurrences : 1;

        foreach (var e in externalEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = (e.DestinationIP, e.DestinationPort);
            if (counts[key] > maxOccurrences)
                continue;

            if (!bySource.TryGetValue(e.SourceIP, out var list))
            {
                list = new List<(string, int, DateTime)>();
                bySource[e.SourceIP] = list;
            }
            list.Add((e.DestinationIP, e.DestinationPort, e.Timestamp));
        }

        var findings = new List<Core.Finding>();

        foreach (var kvp in bySource)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var source = kvp.Key;
            var destinations = kvp.Value;
            var minTime = destinations.Min(d => d.Timestamp);
            var maxTime = destinations.Max(d => d.Timestamp);

            // Deduplicate by destination — same (DstIP, DstPort) may appear
            // multiple times when NoveltyMaxGlobalOccurrences > 1.
            var uniqueDests = destinations
                .Select(d => (d.DstIP, d.DstPort))
                .Distinct()
                .ToList();
            var sampleTargets = uniqueDests
                .Select(d => $"{d.DstIP}:{d.DstPort}")
                .Take(5)
                .ToList();
            var targetList = sampleTargets.Count < uniqueDests.Count
                ? $"{string.Join(", ", sampleTargets)}, ..."
                : string.Join(", ", sampleTargets);

            var occurrenceWord = maxOccurrences == 1 ? "exactly once" : $"at most {maxOccurrences} time(s)";

            var signals = new List<EvidenceSignal>
            {
                new EvidenceSignal
                {
                    Name = "Novel external destinations",
                    Source = EvidenceSignal.BehaviorSource,
                    Explanation = $"Source {source} contacted {uniqueDests.Count} external destination(s) {occurrenceWord}"
                }
            };
            findings.Add(new Core.Finding
            {
                Category = FindingCategories.Novelty,
                Severity = Core.Severity.Low,
                Confidence = FindingConfidenceCalculator.Calculate(signals),
                SourceHost = source,
                Target = targetList,
                TimeRangeStart = minTime,
                TimeRangeEnd = maxTime,
                ShortDescription = $"{uniqueDests.Count} novel destination(s) from {source}",
                Details = $"Source {source} contacted {uniqueDests.Count} external destination(s) {occurrenceWord}. This may indicate reconnaissance or testing of exfiltration channels.",
                MitreTechniques = s_mitreTechniques,
                EvidenceSignals = signals
            });
        }

        return new DetectionResult(findings);
    }
}
