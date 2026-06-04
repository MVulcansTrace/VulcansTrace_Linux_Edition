using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects flood/denial-of-service (DoS) attacks based on high event volume.
/// </summary>
/// <remarks>
/// A flood is identified when a single source IP generates an unusually high number
/// of connection events within a short time window, potentially indicating a DoS attack
/// or compromised host participating in a botnet.
/// </remarks>
public sealed class FloodDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1498", TechniqueName = "Network Denial of Service", Tactic = "Impact", WhyItMatters = "High-volume traffic floods are a classic network DoS attack pattern." },
        new MitreTechnique { TechniqueId = "T1499", TechniqueName = "Endpoint Denial of Service", Tactic = "Impact", WhyItMatters = "Flood traffic can exhaust endpoint resources and degrade availability." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableFlood || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();

        var bySrc = events.GroupBy(e => e.SourceIP);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var srcIp = srcGroup.Key;

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count == 0) continue;

            var windowSeconds = profile.FloodWindowSeconds;

            int start = 0;
            bool inFinding = false;
            int peakCount = 0;

            for (int end = 0; end < ordered.Count; end++)
            {
                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalSeconds > windowSeconds)
                {
                    start++;
                }

                int windowCount = end - start + 1;
                if (windowCount >= profile.FloodMinEvents)
                {
                    if (!inFinding)
                    {
                        peakCount = windowCount;
                        findings.Add(new Core.Finding
                        {
                            Category = FindingCategories.Flood,
                            Severity = Core.Severity.High,
                            SourceHost = srcIp,
                            Target = "multiple hosts/ports",
                            TimeRangeStart = ordered[start].Timestamp,
                            TimeRangeEnd = ordered[end].Timestamp,
                            ShortDescription = $"Flood detected from {srcIp}",
                            Details = $"Detected {windowCount} events within {windowSeconds} seconds.",
                            MitreTechniques = s_mitreTechniques
                        });
                        inFinding = true;
                    }
                    else if (windowCount > peakCount)
                    {
                        peakCount = windowCount;
                    }
                    // No mutation on every iteration — defer to exit or loop end
                }
                else if (inFinding)
                {
                    // Finalize: one mutation to set correct TimeRangeEnd and Details
                    var idx = findings.Count - 1;
                    findings[idx] = findings[idx] with
                    {
                        TimeRangeEnd = ordered[Math.Max(0, end - 1)].Timestamp,
                        Details = $"Detected {peakCount} events within {windowSeconds} seconds."
                    };
                    inFinding = false;
                }
            }

            // Finalize if still in finding at loop end
            if (inFinding)
            {
                var idx = findings.Count - 1;
                findings[idx] = findings[idx] with
                {
                    TimeRangeEnd = ordered[^1].Timestamp,
                    Details = $"Detected {peakCount} events within {windowSeconds} seconds."
                };
            }
        }

        return new DetectionResult(findings);
    }
}
