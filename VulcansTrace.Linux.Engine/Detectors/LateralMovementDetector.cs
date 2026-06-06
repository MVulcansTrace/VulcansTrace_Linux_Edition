using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Net;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects lateral movement patterns indicating internal network traversal by an attacker.
/// </summary>
/// <remarks>
/// Lateral movement is identified when an internal host connects to multiple other internal
/// hosts on administrative ports (e.g., SMB/445, RDP/3389, SSH/22) within a time window.
/// This behavior suggests an attacker pivoting through the network after initial compromise.
/// </remarks>
public sealed class LateralMovementDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1021", TechniqueName = "Remote Services", Tactic = "Lateral Movement", WhyItMatters = "Lateral movement often exploits remote services to pivot between internal hosts." },
        new MitreTechnique { TechniqueId = "T1210", TechniqueName = "Exploitation of Remote Services", Tactic = "Lateral Movement", WhyItMatters = "An attacker may exploit remote services to move laterally after initial compromise." }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableLateralMovement || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();

        var adminPorts = profile.AdminPorts ?? Array.Empty<int>();
        var adminSet = new HashSet<int>(adminPorts);

        var filtered = events.Where(e =>
            IpClassification.IsInternal(e.SourceIP) &&
            IpClassification.IsInternal(e.DestinationIP) &&
            adminSet.Contains(e.DestinationPort));

        var bySrc = filtered.GroupBy(e => e.SourceIP);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count == 0) continue;

            var windowMinutes = profile.LateralWindowMinutes;
            var hostCounts = new Dictionary<string, int>();
            var distinctHosts = 0;
            int start = 0;
            bool inFinding = false;
            int peakDistinctHosts = 0;

            for (int end = 0; end < ordered.Count; end++)
            {
                var addHost = ordered[end].DestinationIP;
                if (hostCounts.TryGetValue(addHost, out var cnt))
                {
                    hostCounts[addHost] = cnt + 1;
                }
                else
                {
                    hostCounts[addHost] = 1;
                    distinctHosts++;
                }

                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
                {
                    var removeHost = ordered[start].DestinationIP;
                    hostCounts[removeHost]--;
                    if (hostCounts[removeHost] == 0)
                    {
                        hostCounts.Remove(removeHost);
                        distinctHosts--;
                    }
                    start++;
                }

                if (distinctHosts >= profile.LateralMinHosts)
                {
                    if (!inFinding)
                    {
                        peakDistinctHosts = distinctHosts;
                        var signals = new List<EvidenceSignal>
                        {
                            new EvidenceSignal
                            {
                                Name = "Multiple internal admin-port contacts",
                                Source = EvidenceSignal.BehaviorSource,
                                Explanation = $"Contacted {distinctHosts} internal hosts on admin ports within {windowMinutes} minutes"
                            }
                        };
                        findings.Add(new Core.Finding
                        {
                            Category = FindingCategories.LateralMovement,
                            Severity = Core.Severity.High,
                            Confidence = FindingConfidenceCalculator.Calculate(signals),
                            SourceHost = srcGroup.Key,
                            Target = "multiple internal hosts",
                            TimeRangeStart = ordered[start].Timestamp,
                            TimeRangeEnd = ordered[end].Timestamp,
                            ShortDescription = $"Lateral movement from {srcGroup.Key}",
                            Details = $"Contacted {distinctHosts} internal hosts on admin ports.",
                            MitreTechniques = s_mitreTechniques,
                            EvidenceSignals = signals
                        });
                        inFinding = true;
                    }
                    else if (distinctHosts > peakDistinctHosts)
                    {
                        peakDistinctHosts = distinctHosts;
                    }
                }
                else if (inFinding)
                {
                    var idx = findings.Count - 1;
                    findings[idx] = findings[idx] with
                    {
                        TimeRangeEnd = ordered[Math.Max(0, end - 1)].Timestamp,
                        Details = $"Contacted {peakDistinctHosts} internal hosts on admin ports."
                    };
                    inFinding = false;
                }
            }

            if (inFinding)
            {
                var idx = findings.Count - 1;
                findings[idx] = findings[idx] with
                {
                    TimeRangeEnd = ordered[^1].Timestamp,
                    Details = $"Contacted {peakDistinctHosts} internal hosts on admin ports."
                };
            }
        }

        return new DetectionResult(findings);
    }
}
