using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Detects potential privilege escalation indicators by monitoring for suspicious admin access patterns.
/// </summary>
/// <remarks>
/// This detector looks for network-level patterns that might indicate attempted privilege escalation:
/// - Rapid succession of admin port access attempts from the same source
/// - Sweeps across multiple administrative ports in a short window
/// </remarks>
public sealed class PrivilegeEscalationDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnablePrivilegeEscalationDetection || events.Count == 0)
        {
            return DetectionResult.Empty;
        }

        var findings = new List<Core.Finding>();
        var baselineAdminPorts = new[] { 22, 2222, 2200, 22022, 3389, 5900, 5432, 3306 };
        var adminPorts = profile.AdminPorts is { Count: > 0 }
            ? profile.AdminPorts.Concat(baselineAdminPorts).Distinct().ToArray()
            : baselineAdminPorts;

        // Group events by source IP and look for admin access patterns
        var bySource = events
            .Where(e => IsAdminAccess(e, adminPorts))
            .GroupBy(e => e.SourceIP);

        foreach (var sourceGroup in bySource)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var orderedEvents = sourceGroup.OrderBy(e => e.Timestamp).ToList();
            
            // Look for rapid succession of admin port access attempts
            var adminSpikes = DetectAdminSpikes(orderedEvents, profile.PrivilegeSpikeWindowMinutes, profile);
            findings.AddRange(adminSpikes);

            // Look for sweeps across multiple admin ports in a short window
            var escalationPatterns = DetectAdminPortSweeps(orderedEvents, profile.PrivilegeSpikeWindowMinutes, profile);
            findings.AddRange(escalationPatterns);
        }

        return new DetectionResult(findings);
    }

    private static bool IsAdminAccess(UnifiedEvent evt, IReadOnlyCollection<int> adminPorts)
    {
        return adminPorts.Contains(evt.DestinationPort);
    }

    private static List<Core.Finding> DetectAdminSpikes(List<UnifiedEvent> events, int windowMinutes, AnalysisProfile profile)
    {
        var findings = new List<Core.Finding>();
        if (windowMinutes <= 0)
        {
            return findings;
        }

        var minAttempts = profile.PrivilegeSpikeMinAttempts > 0 ? profile.PrivilegeSpikeMinAttempts : 5;

        // Sliding window: advance the start pointer so all events in the
        // window fall within the configured time span.
        int start = 0;
        bool inFinding = false;
        int peakCount = 0;

        for (int end = 0; end < events.Count; end++)
        {
            while (start < end &&
                   (events[end].Timestamp - events[start].Timestamp).TotalMinutes > windowMinutes)
            {
                start++;
            }

            int windowCount = end - start + 1;
            if (windowCount >= minAttempts)
            {
                if (!inFinding)
                {
                    peakCount = windowCount;
                    var sourceIp = events[start].SourceIP;
                    findings.Add(new Core.Finding
                    {
                        Category = FindingCategories.PrivilegeEscalation,
                        Severity = Core.Severity.High,
                        SourceHost = sourceIp,
                        Target = $"admin ports in {windowMinutes}min window",
                        TimeRangeStart = events[start].Timestamp,
                        TimeRangeEnd = events[end].Timestamp,
                        ShortDescription = $"Potential privilege escalation indicator: {windowCount} admin access attempts from {sourceIp}",
                        Details = $"Detected {windowCount} admin port access attempts within {windowMinutes} minutes, suggesting possible brute force or escalation activity."
                    });
                    inFinding = true;
                }
                else if (windowCount > peakCount)
                {
                    peakCount = windowCount;
                }
            }
            else if (inFinding)
            {
                var idx = findings.Count - 1;
                findings[idx] = findings[idx] with
                {
                    TimeRangeEnd = events[Math.Max(0, end - 1)].Timestamp,
                    Details = $"Detected {peakCount} admin port access attempts within {windowMinutes} minutes, suggesting possible brute force or escalation activity."
                };
                inFinding = false;
            }
        }

        if (inFinding)
        {
            var idx = findings.Count - 1;
            findings[idx] = findings[idx] with
            {
                TimeRangeEnd = events[^1].Timestamp,
                Details = $"Detected {peakCount} admin port access attempts within {windowMinutes} minutes, suggesting possible brute force or escalation activity."
            };
        }

        return findings;
    }

    private static List<Core.Finding> DetectAdminPortSweeps(List<UnifiedEvent> events, int windowMinutes, AnalysisProfile profile)
    {
        var findings = new List<Core.Finding>();

        if (events.Count < 3 || windowMinutes <= 0)
        {
            return findings;
        }

        var minDistinctPorts = profile.PrivilegeSweepMinDistinctPorts > 0 ? profile.PrivilegeSweepMinDistinctPorts : 3;

        var portCounts = new Dictionary<int, int>();
        var distinctPorts = 0;
        int start = 0;
        bool inFinding = false;
        int peakDistinctPorts = 0;
        List<int>? peakPortList = null;

        for (int end = 0; end < events.Count; end++)
        {
            var addPort = events[end].DestinationPort;
            if (portCounts.TryGetValue(addPort, out var cnt))
            {
                portCounts[addPort] = cnt + 1;
            }
            else
            {
                portCounts[addPort] = 1;
                distinctPorts++;
            }

            while (start < end &&
                   (events[end].Timestamp - events[start].Timestamp).TotalMinutes > windowMinutes)
            {
                var removePort = events[start].DestinationPort;
                portCounts[removePort]--;
                if (portCounts[removePort] == 0)
                {
                    portCounts.Remove(removePort);
                    distinctPorts--;
                }
                start++;
            }

            if (distinctPorts >= minDistinctPorts)
            {
                if (!inFinding)
                {
                    peakDistinctPorts = distinctPorts;
                    peakPortList = portCounts.Keys.ToList();
                    var sourceIp = events[start].SourceIP;
                    var portList = peakPortList;

                    findings.Add(new Core.Finding
                    {
                        Category = FindingCategories.PrivilegeEscalation,
                        Severity = Core.Severity.Medium,
                        SourceHost = sourceIp,
                        Target = $"ports {string.Join(", ", portList.Take(5))}{(portList.Count > 5 ? "..." : "")}",
                        TimeRangeStart = events[start].Timestamp,
                        TimeRangeEnd = events[end].Timestamp,
                        ShortDescription = $"Admin port sweep from {sourceIp}",
                        Details = $"Detected access attempts across {distinctPorts} admin ports within {windowMinutes} minutes."
                    });
                    inFinding = true;
                }
                else if (distinctPorts > peakDistinctPorts)
                {
                    peakDistinctPorts = distinctPorts;
                    peakPortList = portCounts.Keys.ToList();
                }
            }
            else if (inFinding)
            {
                var portList = peakPortList ?? portCounts.Keys.ToList();
                var idx = findings.Count - 1;
                findings[idx] = findings[idx] with
                {
                    TimeRangeEnd = events[Math.Max(0, end - 1)].Timestamp,
                    Target = $"ports {string.Join(", ", portList.Take(5))}{(portList.Count > 5 ? "..." : "")}",
                    Details = $"Detected access attempts across {peakDistinctPorts} admin ports within {windowMinutes} minutes."
                };
                inFinding = false;
            }
        }

        if (inFinding)
        {
            var portList = peakPortList ?? portCounts.Keys.ToList();
            var idx = findings.Count - 1;
            findings[idx] = findings[idx] with
            {
                TimeRangeEnd = events[^1].Timestamp,
                Target = $"ports {string.Join(", ", portList.Take(5))}{(portList.Count > 5 ? "..." : "")}",
                Details = $"Detected access attempts across {peakDistinctPorts} admin ports within {windowMinutes} minutes."
            };
        }

        return findings;
    }
}
