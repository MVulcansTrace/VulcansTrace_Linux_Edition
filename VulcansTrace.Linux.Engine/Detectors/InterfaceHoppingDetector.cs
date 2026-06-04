using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects rapid interface switching which may indicate network reconnaissance or evasion tactics.
/// </summary>
/// <remarks>
/// This detector monitors for scenarios where a single source IP address sends traffic
/// through multiple different network interfaces within a short time window. This behavior
/// may indicate:
/// - Network interface enumeration
/// - Bypassing network segmentation
/// - Multi-homed attack scenarios
/// - Network reconnaissance
/// </remarks>
public sealed class InterfaceHoppingDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1595", TechniqueName = "Active Scanning", Tactic = "Reconnaissance", WhyItMatters = "Rapid interface switching can indicate active scanning and network enumeration." },
        new MitreTechnique { TechniqueId = "T1018", TechniqueName = "Remote System Discovery", Tactic = "Discovery", WhyItMatters = "Hopping between interfaces may be used to discover remote systems across network segments." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableInterfaceHopping || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();
        var windowMinutes = profile.InterfaceHoppingWindowMinutes > 0 ? profile.InterfaceHoppingWindowMinutes : 5;

        // Group by source IP
        var byIp = events.GroupBy(e => e.SourceIP);

        foreach (var ipGroup in byIp)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ip = ipGroup.Key;

            // Filter to events that have an interface, then order by time
            var ordered = ipGroup
                .Where(e => !string.IsNullOrEmpty(e.LinuxSpecific.GetValueOrDefault("InterfaceIn", "")))
                .OrderBy(e => e.Timestamp)
                .ToList();

            if (ordered.Count < 2)
                continue;

            // Sliding window: track distinct interfaces within the time window
            var interfaceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var distinctInterfaces = 0;
            int start = 0;
            var bestDistinct = 0;
            var bestStart = 0;
            var bestEnd = 0;
            List<string> bestInterfaces = [];

            for (int end = 0; end < ordered.Count; end++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var addIface = ordered[end].LinuxSpecific.GetValueOrDefault("InterfaceIn", "");

                if (interfaceCounts.TryGetValue(addIface, out var cnt))
                {
                    interfaceCounts[addIface] = cnt + 1;
                }
                else
                {
                    interfaceCounts[addIface] = 1;
                    distinctInterfaces++;
                }

                // Shrink window from the left
                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
                {
                    var removeIface = ordered[start].LinuxSpecific.GetValueOrDefault("InterfaceIn", "");
                    if (!string.IsNullOrEmpty(removeIface) && interfaceCounts.TryGetValue(removeIface, out var removeCnt))
                    {
                        interfaceCounts[removeIface] = removeCnt - 1;
                        if (interfaceCounts[removeIface] == 0)
                        {
                            interfaceCounts.Remove(removeIface);
                            distinctInterfaces--;
                        }
                    }
                    start++;
                }

                if (distinctInterfaces > bestDistinct)
                {
                    bestDistinct = distinctInterfaces;
                    bestStart = start;
                    bestEnd = end;
                    bestInterfaces = interfaceCounts.Keys.OrderBy(i => i, StringComparer.OrdinalIgnoreCase).ToList();
                }
            }

            if (bestDistinct > 1)
            {
                var minTime = ordered[bestStart].Timestamp;
                var maxTime = ordered[bestEnd].Timestamp;

                findings.Add(new Core.Finding
                {
                    Category = FindingCategories.InterfaceHopping,
                    Severity = Core.Severity.Medium,
                    SourceHost = ip,
                    Target = $"{bestInterfaces.Count} network interfaces",
                    TimeRangeStart = minTime,
                    TimeRangeEnd = maxTime,
                    ShortDescription = $"Interface hopping detected from {ip}",
                    Details = $"Source IP {ip} sent traffic through {bestInterfaces.Count} different network interfaces ({string.Join(", ", bestInterfaces)}) within {windowMinutes} minutes. This may indicate network enumeration, bypassing segmentation, or multi-homed attack scenarios.",
                    MitreTechniques = s_mitreTechniques
                });
            }
        }

        return new DetectionResult(findings);
    }
}
