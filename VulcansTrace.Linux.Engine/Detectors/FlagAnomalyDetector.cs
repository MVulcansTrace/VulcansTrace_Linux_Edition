using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

public sealed class FlagAnomalyDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableFlagAnomaly || events.Count == 0)
            return DetectionResult.Empty;

        var groups = new Dictionary<(string SourceIP, string AnomalyType), List<UnifiedEvent>>();

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (evt.Protocol != "TCP")
                continue;

            var flags = evt.LinuxSpecific.GetValueOrDefault("Flags", "").ToUpper();

            if (!string.IsNullOrWhiteSpace(flags) && flags.Contains("FIN") && flags.Contains("PSH") && flags.Contains("URG"))
            {
                Aggregate(evt, "XMAS-scan");
            }
            else if (flags.Contains("FIN") && !flags.Contains("SYN") && !flags.Contains("ACK"))
            {
                Aggregate(evt, "FIN-without-SYN");
            }
        }

        var findings = new List<Core.Finding>();

        var minEvents = profile.FlagAnomalyMinEvents > 0 ? profile.FlagAnomalyMinEvents : 1;

        foreach (var kvp in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var evts = kvp.Value;
            if (evts.Count < minEvents)
                continue;
            var minTime = evts.Min(e => e.Timestamp);
            var maxTime = evts.Max(e => e.Timestamp);
            var distinctTargets = evts.Select(e => $"{e.DestinationIP}:{e.DestinationPort}").Distinct().ToList();
            var sampleTargets = distinctTargets.Take(5).ToList();
            var targetList = sampleTargets.Count < distinctTargets.Count
                ? $"{string.Join(", ", sampleTargets)}, ..."
                : string.Join(", ", sampleTargets);

            var description = kvp.Key.AnomalyType == "FIN-without-SYN"
                ? $"FIN-without-SYN detected from {kvp.Key.SourceIP}"
                : $"XMAS scan detected from {kvp.Key.SourceIP}";

            var detail = kvp.Key.AnomalyType == "FIN-without-SYN"
                ? $"{evts.Count} TCP packet(s) with FIN flag but no SYN from {kvp.Key.SourceIP} to {distinctTargets.Count} target(s). This may indicate stealth port scanning (FIN scan) or network reconnaissance."
                : $"{evts.Count} TCP packet(s) with FIN, PSH, and URG flags set from {kvp.Key.SourceIP} to {distinctTargets.Count} target(s). This indicates an XMAS scan used for port scanning and OS fingerprinting.";

            findings.Add(new Core.Finding
            {
                Category = FindingCategories.FlagAnomaly,
                Severity = Core.Severity.Medium,
                SourceHost = kvp.Key.SourceIP,
                Target = targetList,
                TimeRangeStart = minTime,
                TimeRangeEnd = maxTime,
                ShortDescription = description,
                Details = detail
            });
        }

        return new DetectionResult(findings);

        void Aggregate(UnifiedEvent evt, string anomalyType)
        {
            var key = (evt.SourceIP, anomalyType);
            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<UnifiedEvent>();
                groups[key] = list;
            }
            list.Add(evt);
        }
    }
}
