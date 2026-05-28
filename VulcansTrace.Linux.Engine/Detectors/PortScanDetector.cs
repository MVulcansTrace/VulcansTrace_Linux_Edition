using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects port scanning activity by identifying hosts probing multiple destination ports.
/// </summary>
/// <remarks>
/// A port scan is identified when a single source IP contacts many distinct destination
/// ports within a configurable time window. This behavior often indicates
/// reconnaissance activity by an attacker mapping network services.
/// </remarks>
public sealed class PortScanDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();

        if (!profile.EnablePortScan || events.Count == 0)
        {
            return DetectionResult.Empty;
        }

        var findings = new List<Core.Finding>();

        var bySrc = events.GroupBy(e => e.SourceIP);
        foreach (var srcGroup in bySrc)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var srcIp = srcGroup.Key;

            var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
            var totalForSource = ordered.Count;

            if (profile.PortScanMaxEntriesPerSource is { } maxEntries && maxEntries > 0 && ordered.Count > maxEntries)
            {
                ordered = ordered.TakeLast(maxEntries).ToList();
                warnings.Add($"Port scan analysis for {srcIp} truncated to {maxEntries} events out of {totalForSource}.");
            }

            var distinctPortsForSource = ordered
                .Select(e => e.DestinationPort)
                .Distinct()
                .Count();

            if (distinctPortsForSource < profile.PortScanMinPorts)
                continue;

            var windowMinutes = profile.PortScanWindowMinutes;
            var portCounts = new Dictionary<int, int>();
            var distinctPorts = 0;
            int start = 0;
            bool inFinding = false;
            int peakDistinctPorts = 0;

            for (int end = 0; end < ordered.Count; end++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var addKey = ordered[end].DestinationPort;
                if (portCounts.TryGetValue(addKey, out var cnt))
                {
                    portCounts[addKey] = cnt + 1;
                }
                else
                {
                    portCounts[addKey] = 1;
                    distinctPorts++;
                }

                while (start < end &&
                       (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
                {
                    var removeKey = ordered[start].DestinationPort;
                    portCounts[removeKey]--;
                    if (portCounts[removeKey] == 0)
                    {
                        portCounts.Remove(removeKey);
                        distinctPorts--;
                    }
                    start++;
                }

                if (distinctPorts >= profile.PortScanMinPorts)
                {
                    if (!inFinding)
                    {
                        peakDistinctPorts = distinctPorts;
                        findings.Add(new Core.Finding
                        {
                            Category = FindingCategories.PortScan,
                            Severity = Core.Severity.Medium,
                            SourceHost = srcIp,
                            Target = "multiple ports",
                            TimeRangeStart = ordered[start].Timestamp,
                            TimeRangeEnd = ordered[end].Timestamp,
                            ShortDescription = $"Port scan detected from {srcIp}",
                            Details = $"Detected {distinctPorts} distinct destination ports within {windowMinutes} minutes."
                        });
                        inFinding = true;
                    }
                    else if (distinctPorts > peakDistinctPorts)
                    {
                        peakDistinctPorts = distinctPorts;
                    }
                }
                else if (inFinding)
                {
                    var idx = findings.Count - 1;
                    findings[idx] = findings[idx] with
                    {
                        TimeRangeEnd = ordered[Math.Max(0, end - 1)].Timestamp,
                        Details = $"Detected {peakDistinctPorts} distinct destination ports within {windowMinutes} minutes."
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
                    Details = $"Detected {peakDistinctPorts} distinct destination ports within {windowMinutes} minutes."
                };
            }
        }

        return new DetectionResult(findings, warnings);
    }
}
