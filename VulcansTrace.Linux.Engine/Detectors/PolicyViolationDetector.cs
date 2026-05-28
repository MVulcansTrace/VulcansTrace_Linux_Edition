using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Net;

namespace VulcansTrace.Linux.Engine.Detectors;

public sealed class PolicyViolationDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnablePolicy || events.Count == 0)
            return DetectionResult.Empty;

        var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());

        var groups = new Dictionary<(string SourceIP, int DstPort), List<UnifiedEvent>>();

        foreach (var e in events)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IpClassification.IsInternal(e.SourceIP))
                continue;

            if (!IpClassification.IsExternal(e.DestinationIP))
                continue;

            if (!disallowed.Contains(e.DestinationPort))
                continue;

            var key = (e.SourceIP, e.DestinationPort);
            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<UnifiedEvent>();
                groups[key] = list;
            }
            list.Add(e);
        }

        var findings = new List<Core.Finding>();

        var minEvents = profile.PolicyViolationMinEvents > 0 ? profile.PolicyViolationMinEvents : 1;

        foreach (var kvp in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var evts = kvp.Value;
            if (evts.Count < minEvents)
                continue;
            var minTime = evts.Min(e => e.Timestamp);
            var maxTime = evts.Max(e => e.Timestamp);
            var distinctTargetIps = evts.Select(e => e.DestinationIP).Distinct().ToList();

            findings.Add(new Core.Finding
            {
                Category = FindingCategories.PolicyViolation,
                Severity = Core.Severity.High,
                SourceHost = kvp.Key.SourceIP,
                Target = distinctTargetIps.Count == 1
                    ? $"{distinctTargetIps[0]}:{kvp.Key.DstPort}"
                    : $"multiple hosts:{kvp.Key.DstPort}",
                TimeRangeStart = minTime,
                TimeRangeEnd = maxTime,
                ShortDescription = $"Disallowed outbound port {kvp.Key.DstPort} from {kvp.Key.SourceIP}",
                Details = $"{evts.Count} outbound connection(s) to {distinctTargetIps.Count} destination(s) on disallowed port {kvp.Key.DstPort} from {kvp.Key.SourceIP}."
            });
        }

        return new DetectionResult(findings);
    }
}
