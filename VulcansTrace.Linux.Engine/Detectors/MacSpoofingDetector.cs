using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Parsing;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects potential MAC address spoofing by tracking MAC-to-IP associations.
/// </summary>
/// <remarks>
/// This detector monitors for scenarios where a single IP address is associated with
/// multiple different MAC addresses within a short time window. This behavior may
/// indicate:
/// - MAC spoofing attacks
/// - ARP poisoning
/// - Network masquerading
/// - Virtual machine migration or cloning
/// </remarks>
public sealed class MacSpoofingDetector : IDetector
{
    private const int DefaultWindowMinutes = 5;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableMacSpoofing || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();
        var windowMinutes = profile.MacSpoofingWindowMinutes > 0
            ? profile.MacSpoofingWindowMinutes
            : DefaultWindowMinutes;

        // Group by IP address
        var byIp = events.GroupBy(e => e.SourceIP);

        foreach (var ipGroup in byIp)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ip = ipGroup.Key;

            var ordered = ipGroup
                .Where(e => !string.IsNullOrEmpty(e.LinuxSpecific.GetValueOrDefault("MAC", "")))
                .Select(e => new
                {
                    Event = e,
                    Mac = FirewallLogRegex.NormalizeMacField(e.LinuxSpecific.GetValueOrDefault("MAC", ""))
                })
                .Where(e => !string.IsNullOrEmpty(e.Mac))
                .OrderBy(e => e.Event.Timestamp)
                .ToList();

            if (ordered.Count < 2)
                continue;

            var macCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var distinctMacs = 0;
            var start = 0;
            var bestDistinctMacs = 0;
            var bestStart = 0;
            var bestEnd = 0;
            List<string> bestMacAddresses = [];

            for (var end = 0; end < ordered.Count; end++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var addMac = ordered[end].Mac;
                if (macCounts.TryGetValue(addMac, out var count))
                {
                    macCounts[addMac] = count + 1;
                }
                else
                {
                    macCounts[addMac] = 1;
                    distinctMacs++;
                }

                while (start < end &&
                       (ordered[end].Event.Timestamp - ordered[start].Event.Timestamp).TotalMinutes > windowMinutes)
                {
                    var removeMac = ordered[start].Mac;
                    macCounts[removeMac]--;
                    if (macCounts[removeMac] == 0)
                    {
                        macCounts.Remove(removeMac);
                        distinctMacs--;
                    }
                    start++;
                }

                if (distinctMacs > bestDistinctMacs)
                {
                    bestDistinctMacs = distinctMacs;
                    bestStart = start;
                    bestEnd = end;
                    bestMacAddresses = macCounts.Keys.OrderBy(mac => mac, StringComparer.OrdinalIgnoreCase).ToList();
                }
            }

            if (bestDistinctMacs > 1)
            {
                var minTime = ordered[bestStart].Event.Timestamp;
                var maxTime = ordered[bestEnd].Event.Timestamp;

                findings.Add(new Core.Finding
                {
                    Category = FindingCategories.MacSpoofing,
                    Severity = Core.Severity.High,
                    SourceHost = ip,
                    Target = "multiple MAC addresses",
                    TimeRangeStart = minTime,
                    TimeRangeEnd = maxTime,
                    ShortDescription = $"Potential MAC spoofing from {ip}",
                    Details = $"IP address {ip} is associated with {bestMacAddresses.Count} different MAC addresses within {windowMinutes} minutes: {string.Join(", ", bestMacAddresses)}. This may indicate MAC address spoofing, ARP poisoning, or network masquerading."
                });
            }
        }

        return new DetectionResult(findings);
    }
}
