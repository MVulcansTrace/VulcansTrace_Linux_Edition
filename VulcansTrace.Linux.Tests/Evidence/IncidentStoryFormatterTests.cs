using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class IncidentStoryFormatterTests
{
    private readonly IncidentStoryFormatter _formatter = new();

    [Fact]
    public void Format_EmptyFindings_ReturnsNoFindingsResult()
    {
        var traceMap = new TraceMapResult
        {
            Findings = Array.Empty<Finding>(),
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Empty(result.Beats);
        Assert.Equal("No findings.", result.LikelyChain);
        Assert.False(result.HasCriticalChain);
        Assert.Empty(result.Recommendations);
        Assert.Equal("No findings to narrate.", result.Markdown);
    }

    [Fact]
    public void Format_WithCriticalChain_SetsHasCriticalChainAndChainCategories()
    {
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Beaconing",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.10",
            Target = "internal",
            TimeRangeStart = DateTime.UnixEpoch.AddMinutes(10),
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Severity = Severity.High
        };
        var f3 = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            SourceHost = "192.168.1.10",
            Target = "admin",
            TimeRangeStart = DateTime.UnixEpoch.AddMinutes(20),
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(25),
            ShortDescription = "Privilege escalation",
            Severity = Severity.Critical
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { f1, f2, f3 },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "192.168.1.10",
                    Narrative = "Critical chain",
                    FindingIds = new[] { f1.Id, f2.Id, f3.Id }
                }
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.True(result.HasCriticalChain);
        Assert.Contains("C2", result.LikelyChain);
        Assert.Contains("Lateral Movement", result.LikelyChain);
        Assert.Contains("Privilege Escalation", result.LikelyChain);
        Assert.Equal(3, result.Beats.Count);
        Assert.Equal(DateTime.UnixEpoch, result.Beats[0].Timestamp);
        Assert.Equal(FindingCategories.Beaconing, result.Beats[0].Category);
    }

    [Fact]
    public void Format_WithEdgesNoCriticalChain_UsesLongestChainCategories()
    {
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Beaconing",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.10",
            Target = "internal",
            TimeRangeStart = DateTime.UnixEpoch.AddMinutes(10),
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Severity = Severity.High
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { f1, f2 },
            Edges = new[]
            {
                new CorrelationEdge(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Edge", CorrelationConfidence.High)
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.False(result.HasCriticalChain);
        Assert.Contains("C2", result.LikelyChain);
        Assert.Contains("Lateral Movement", result.LikelyChain);
    }

    [Fact]
    public void Format_LongestChainCategories_CollapsesAdjacentDuplicatesButPreservesReEntry()
    {
        // Beaconing -> Lateral -> Beaconing re-entry should NOT be flattened
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Beaconing 1",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.10",
            Target = "internal",
            TimeRangeStart = DateTime.UnixEpoch.AddMinutes(10),
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(15),
            ShortDescription = "Lateral",
            Severity = Severity.High
        };
        var f3 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.6:443",
            TimeRangeStart = DateTime.UnixEpoch.AddMinutes(20),
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(25),
            ShortDescription = "Beaconing 2",
            Severity = Severity.High
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { f1, f2, f3 },
            Edges = new[]
            {
                new CorrelationEdge(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Edge1", CorrelationConfidence.High),
                new CorrelationEdge(f2.Id, f3.Id, CorrelationType.EscalatesTo, "Edge2", CorrelationConfidence.High)
            }
        };

        var result = _formatter.Format(traceMap);

        // "C2" should appear twice because Beaconing re-enters after Lateral
        var c2Count = result.LikelyChain.Split("C2").Length - 1;
        Assert.Equal(2, c2Count);
    }

    [Fact]
    public void Format_Markdown_DoesNotPrintTimestampTwice()
    {
        var finding = CreateFinding(FindingCategories.Beaconing, DateTime.UnixEpoch);
        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Equal("beaconing began.", result.Beats[0].Narrative);
        Assert.Equal("00:00", result.Beats[0].TimestampLabel);
        Assert.Contains("- **00:00** — beaconing began.", result.Markdown);
        Assert.DoesNotContain("— At 00:00", result.Markdown);
    }

    [Fact]
    public void Format_CriticalChainWithUndatedFinding_KeepsBeatVisible()
    {
        var beaconing = CreateFinding(FindingCategories.Beaconing, DateTime.MinValue);
        var lateral = CreateFinding(FindingCategories.LateralMovement, DateTime.UnixEpoch.AddMinutes(10));
        var privEsc = CreateFinding(FindingCategories.PrivilegeEscalation, DateTime.UnixEpoch.AddMinutes(20));
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral, privEsc },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "host-a",
                    Narrative = "chain",
                    FindingIds = new[] { beaconing.Id, lateral.Id, privEsc.Id }
                }
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Equal(3, result.Beats.Count);
        var undatedBeat = Assert.Single(result.Beats, b => !b.HasTimestamp);
        Assert.Equal("unknown time", undatedBeat.TimestampLabel);
        Assert.Contains("C2 → Lateral Movement → Privilege Escalation", result.LikelyChain);
        Assert.Contains("- **unknown time** — beaconing began.", result.Markdown);
    }

    [Fact]
    public void Format_MultiDayFindings_UsesDateAwareTimestampLabels()
    {
        var first = CreateFinding(FindingCategories.Beaconing, new DateTime(2026, 6, 5, 3, 14, 0, DateTimeKind.Utc));
        var second = CreateFinding(FindingCategories.LateralMovement, new DateTime(2026, 6, 6, 3, 14, 0, DateTimeKind.Utc));
        var traceMap = new TraceMapResult
        {
            Findings = new[] { first, second },
            Edges = new[]
            {
                new CorrelationEdge(first.Id, second.Id, CorrelationType.TemporalSequence, "next day", CorrelationConfidence.Medium)
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Equal("2026-06-05 03:14", result.Beats[0].TimestampLabel);
        Assert.Equal("2026-06-06 03:14", result.Beats[1].TimestampLabel);
        Assert.Contains("- **2026-06-05 03:14** — beaconing began.", result.Markdown);
        Assert.Contains("- **2026-06-06 03:14** — lateral movement appeared.", result.Markdown);
    }

    [Fact]
    public void Format_MultipleCriticalChains_NarratesEachChain()
    {
        var a1 = CreateFinding(FindingCategories.Beaconing, DateTime.UnixEpoch, "host-a");
        var a2 = CreateFinding(FindingCategories.LateralMovement, DateTime.UnixEpoch.AddMinutes(1), "host-a");
        var a3 = CreateFinding(FindingCategories.PrivilegeEscalation, DateTime.UnixEpoch.AddMinutes(2), "host-a");
        var b1 = CreateFinding(FindingCategories.Beaconing, DateTime.UnixEpoch.AddMinutes(3), "host-b");
        var b2 = CreateFinding(FindingCategories.LateralMovement, DateTime.UnixEpoch.AddMinutes(4), "host-b");
        var b3 = CreateFinding(FindingCategories.PrivilegeEscalation, DateTime.UnixEpoch.AddMinutes(5), "host-b");
        var traceMap = new TraceMapResult
        {
            Findings = new[] { a1, a2, a3, b1, b2, b3 },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "host-a",
                    Narrative = "chain-a",
                    FindingIds = new[] { a1.Id, a2.Id, a3.Id }
                },
                new CriticalChain
                {
                    Host = "host-b",
                    Narrative = "chain-b",
                    FindingIds = new[] { b1.Id, b2.Id, b3.Id }
                }
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Contains("Likely chains:", result.LikelyChain);
        Assert.Contains("host-a: C2 → Lateral Movement → Privilege Escalation", result.LikelyChain);
        Assert.Contains("host-b: C2 → Lateral Movement → Privilege Escalation", result.LikelyChain);
        Assert.Contains("- host-a: C2 → Lateral Movement → Privilege Escalation", result.Markdown);
        Assert.Contains("- host-b: C2 → Lateral Movement → Privilege Escalation", result.Markdown);
    }

    [Fact]
    public void Format_UnknownCategory_UsesConsistentDisplayName()
    {
        var first = CreateFinding("SuspiciousX", DateTime.UnixEpoch);
        var second = CreateFinding("FollowOnY", DateTime.UnixEpoch.AddMinutes(1));
        var traceMap = new TraceMapResult
        {
            Findings = new[] { first, second },
            Edges = new[]
            {
                new CorrelationEdge(first.Id, second.Id, CorrelationType.TemporalSequence, "unknown chain", CorrelationConfidence.Medium)
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Contains(result.Beats, b => b.Narrative == "SuspiciousX was detected.");
        Assert.Contains("SuspiciousX → FollowOnY", result.LikelyChain);
        Assert.DoesNotContain("suspiciousx", result.Markdown);
    }

    [Fact]
    public void Format_DisconnectedEdges_DoesNotMergeIntoFictionalChain()
    {
        var beaconing = CreateFinding(FindingCategories.Beaconing, DateTime.UnixEpoch);
        var lateral = CreateFinding(FindingCategories.LateralMovement, DateTime.UnixEpoch.AddMinutes(1));
        var portScan = CreateFinding(FindingCategories.PortScan, DateTime.UnixEpoch.AddMinutes(2), "host-b");
        var flood = CreateFinding(FindingCategories.Flood, DateTime.UnixEpoch.AddMinutes(3), "host-b");
        var traceMap = new TraceMapResult
        {
            Findings = new[] { beaconing, lateral, portScan, flood },
            Edges = new[]
            {
                new CorrelationEdge(beaconing.Id, lateral.Id, CorrelationType.EscalatesTo, "first pair", CorrelationConfidence.High),
                new CorrelationEdge(portScan.Id, flood.Id, CorrelationType.TemporalSequence, "second pair", CorrelationConfidence.Medium)
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Equal("Likely chain: C2 → Lateral Movement.", result.LikelyChain);
        Assert.DoesNotContain("Port Scan", result.LikelyChain);
        Assert.DoesNotContain("Flood", result.LikelyChain);
    }

    [Theory]
    [InlineData(FindingCategories.Beaconing, "began")]
    [InlineData(FindingCategories.LateralMovement, "appeared")]
    [InlineData(FindingCategories.PrivilegeEscalation, "indicators were observed")]
    [InlineData(FindingCategories.PortScan, "activity was detected")]
    [InlineData(FindingCategories.Flood, "indicators were observed")]
    [InlineData(FindingCategories.C2Channel, "channel activity was detected")]
    [InlineData(FindingCategories.PolicyViolation, "violations were detected")]
    [InlineData(FindingCategories.Novelty, "novel activity was observed")]
    [InlineData(FindingCategories.FlagAnomaly, "anomalies were observed")]
    [InlineData(FindingCategories.MacSpoofing, "was detected")]
    [InlineData(FindingCategories.InterfaceHopping, "was detected")]
    [InlineData(FindingCategories.UnusualPacketSize, "packets were observed")]
    [InlineData(FindingCategories.KernelModule, "module load was detected")]
    [InlineData(FindingCategories.UserAccount, "account anomalies were observed")]
    [InlineData(FindingCategories.FilesystemAudit, "filesystem anomalies were detected")]
    [InlineData(FindingCategories.CronJob, "suspicious job activity was detected")]
    [InlineData(FindingCategories.PackageVulnerability, "vulnerable packages were found")]
    [InlineData(FindingCategories.Container, "container anomalies were detected")]
    [InlineData(FindingCategories.Kubernetes, "kubernetes anomalies were detected")]
    [InlineData(FindingCategories.ThreatIntel, "threat intel matches were found")]
    [InlineData(FindingCategories.Yara, "signature matches were found")]
    [InlineData(FindingCategories.ProcessRuntime, "runtime anomalies were detected")]
    public void VerbForCategory_MapsEveryKnownCategory(string category, string expectedVerb)
    {
        var finding = new Finding
        {
            Category = category,
            SourceHost = "host",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "desc",
            Severity = Severity.Info
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Single(result.Beats);
        Assert.EndsWith($" {expectedVerb}.", result.Beats[0].Narrative);
    }

    [Theory]
    [InlineData(FindingCategories.Beaconing, "C2")]
    [InlineData(FindingCategories.LateralMovement, "Lateral Movement")]
    [InlineData(FindingCategories.PrivilegeEscalation, "Privilege Escalation")]
    [InlineData(FindingCategories.PortScan, "Port Scan")]
    [InlineData(FindingCategories.Flood, "Flood / DoS")]
    [InlineData(FindingCategories.C2Channel, "C2 Channel")]
    [InlineData(FindingCategories.PolicyViolation, "Policy Violation")]
    [InlineData(FindingCategories.Novelty, "Novelty")]
    [InlineData(FindingCategories.FlagAnomaly, "Flag Anomaly")]
    [InlineData(FindingCategories.MacSpoofing, "MAC Spoofing")]
    [InlineData(FindingCategories.InterfaceHopping, "Interface Hopping")]
    [InlineData(FindingCategories.UnusualPacketSize, "Unusual Packet Size")]
    [InlineData(FindingCategories.KernelModule, "Kernel Module")]
    [InlineData(FindingCategories.UserAccount, "User Account")]
    [InlineData(FindingCategories.FilesystemAudit, "Filesystem Audit")]
    [InlineData(FindingCategories.CronJob, "Cron Job")]
    [InlineData(FindingCategories.PackageVulnerability, "Package Vulnerability")]
    [InlineData(FindingCategories.Container, "Container")]
    [InlineData(FindingCategories.Kubernetes, "Kubernetes")]
    [InlineData(FindingCategories.ThreatIntel, "Threat Intel")]
    [InlineData(FindingCategories.Yara, "YARA")]
    [InlineData(FindingCategories.ProcessRuntime, "Process Runtime")]
    public void DisplayNameForCategory_MapsEveryKnownCategory(string category, string expectedDisplayName)
    {
        var finding = new Finding
        {
            Category = category,
            SourceHost = "host",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "desc",
            Severity = Severity.Info
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>(),
            CriticalChains = new[]
            {
                new CriticalChain
                {
                    Host = "host",
                    Narrative = "chain",
                    FindingIds = new[] { finding.Id }
                }
            }
        };

        var result = _formatter.Format(traceMap);

        Assert.Contains(expectedDisplayName, result.LikelyChain);
    }

    [Fact]
    public void BuildRecommendations_Beaconing_IncludesBlockDestination()
    {
        var finding = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Beaconing",
            Severity = Severity.High
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Contains(result.Recommendations, r => r.Contains("Block outbound destinations", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Recommendations, r => r.Contains("10.0.0.5:443", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildRecommendations_NoRecognizedCategories_ReturnsFallback()
    {
        var finding = new Finding
        {
            Category = "UnknownCategory",
            SourceHost = "192.168.1.10",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Unknown",
            Severity = Severity.Info
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Single(result.Recommendations);
        Assert.Contains("Review findings", result.Recommendations[0]);
    }

    [Fact]
    public void BuildRecommendations_PrivilegeEscalation_IncludesAccountInspection()
    {
        var finding = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            SourceHost = "192.168.1.10",
            Target = "root",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "PrivEsc",
            Severity = Severity.Critical
        };

        var traceMap = new TraceMapResult
        {
            Findings = new[] { finding },
            Edges = Array.Empty<CorrelationEdge>()
        };

        var result = _formatter.Format(traceMap);

        Assert.Contains(result.Recommendations, r => r.Contains("Inspect account changes", StringComparison.OrdinalIgnoreCase));
    }

    private static Finding CreateFinding(string category, DateTime timeRangeStart, string sourceHost = "host")
    {
        return new Finding
        {
            Category = category,
            SourceHost = sourceHost,
            Target = "target",
            TimeRangeStart = timeRangeStart,
            TimeRangeEnd = timeRangeStart == DateTime.MinValue ? DateTime.MinValue : timeRangeStart.AddMinutes(1),
            ShortDescription = category,
            Severity = Severity.Info
        };
    }
}
