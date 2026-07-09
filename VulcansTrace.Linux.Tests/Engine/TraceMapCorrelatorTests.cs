using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Tests.Engine;

public class TraceMapCorrelatorTests
{
    private readonly TraceMapCorrelator _correlator = new();

    [Fact]
    public void Correlate_BeaconingAndLateralMovement_SameSource_CreatesEdge()
    {
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement detected",
            Details = "Contacted 5 internal hosts"
        };

        var result = _correlator.Correlate(new[] { beaconing, lateral });

        Assert.Equal(2, result.Findings.Count);
        Assert.Single(result.Edges);
        var edge = result.Edges[0];
        Assert.Equal(beaconing.Id, edge.FromFindingId);
        Assert.Equal(lateral.Id, edge.ToFindingId);
        Assert.Equal(CorrelationType.EscalatesTo, edge.CorrelationType);
        Assert.Equal(CorrelationConfidence.High, edge.Confidence);
        Assert.Contains("Beaconing", edge.Narrative);
        Assert.Contains("LateralMovement", edge.Narrative);
    }

    [Fact]
    public void Correlate_FlagAnomalyAndPortScan_SameSource_CreatesEdge()
    {
        var baseTime = DateTime.UtcNow;
        var flag = new Finding
        {
            Category = FindingCategories.FlagAnomaly,
            Severity = Severity.Medium,
            SourceHost = "10.0.0.99",
            Target = "192.168.1.1:22",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime,
            ShortDescription = "FIN without SYN",
            Details = "Stealth scan"
        };
        var portScan = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.Medium,
            SourceHost = "10.0.0.99",
            Target = "multiple hosts/ports",
            TimeRangeStart = baseTime.AddMinutes(2),
            TimeRangeEnd = baseTime.AddMinutes(4),
            ShortDescription = "Port scan detected",
            Details = "20 distinct destinations"
        };

        var result = _correlator.Correlate(new[] { flag, portScan });

        Assert.Single(result.Edges);
        Assert.Equal(flag.Id, result.Edges[0].FromFindingId);
        Assert.Equal(portScan.Id, result.Edges[0].ToFindingId);
    }

    [Fact]
    public void Correlate_MacSpoofingAndInterfaceHopping_SameSource_CreatesEdge()
    {
        var baseTime = DateTime.UtcNow;
        var mac = new Finding
        {
            Category = FindingCategories.MacSpoofing,
            Severity = Severity.High,
            SourceHost = "192.168.1.50",
            Target = "multiple MAC addresses",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(10),
            ShortDescription = "MAC spoofing",
            Details = "3 MACs for same IP"
        };
        var iface = new Finding
        {
            Category = FindingCategories.InterfaceHopping,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.50",
            Target = "3 network interfaces",
            TimeRangeStart = baseTime.AddMinutes(5),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Interface hopping",
            Details = "Switched between eth0, eth1, wlan0"
        };

        var result = _correlator.Correlate(new[] { mac, iface });

        Assert.Single(result.Edges);
    }

    [Fact]
    public void Correlate_DifferentSources_NoEdges()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing from host A",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.200",
                Target = "multiple internal hosts",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Lateral movement from host B",
                Details = "Different source"
            }
        };

        var result = _correlator.Correlate(findings);

        Assert.Equal(2, result.Findings.Count);
        Assert.Empty(result.Edges);
    }

    [Fact]
    public void Correlate_EmptyFindings_ReturnsEmpty()
    {
        var result = _correlator.Correlate(Array.Empty<Finding>());

        Assert.Empty(result.Findings);
        Assert.Empty(result.Edges);
    }

    [Fact]
    public void Correlate_UnrelatedFinding_NoEscalationEdgeForIt()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing detected",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = baseTime.AddMinutes(5),
                TimeRangeEnd = baseTime.AddMinutes(10),
                ShortDescription = "Lateral movement detected",
                Details = "Contacted 5 internal hosts"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "multiple hosts/ports",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(2),
                ShortDescription = "Port scan detected",
                Details = "20 distinct destinations"
            }
        };

        var result = _correlator.Correlate(findings);

        Assert.Equal(3, result.Findings.Count);

        // Only one EscalatesTo edge (Beaconing <-> LateralMovement)
        var escalationEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.EscalatesTo).ToList();
        Assert.Single(escalationEdges);
        Assert.NotEqual(FindingCategories.PortScan, result.Findings.Single(f => f.Id == escalationEdges[0].FromFindingId).Category);
        Assert.NotEqual(FindingCategories.PortScan, result.Findings.Single(f => f.Id == escalationEdges[0].ToFindingId).Category);

        // TemporalSequence edges should also exist for consecutive findings on the same host
        Assert.Contains(result.Edges, e => e.CorrelationType == CorrelationType.TemporalSequence);
    }

    [Fact]
    public void Correlate_ConsecutiveFindingsOnSameHost_CreatesTemporalSequenceEdges()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                SourceHost = "10.0.0.1",
                Target = "target-a",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing"
            },
            new()
            {
                Category = FindingCategories.MacSpoofing,
                SourceHost = "10.0.0.1",
                Target = "target-b",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "MAC spoof"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                SourceHost = "10.0.0.1",
                Target = "target-c",
                TimeRangeStart = baseTime.AddMinutes(20),
                TimeRangeEnd = baseTime.AddMinutes(25),
                ShortDescription = "Port scan"
            }
        };

        var result = _correlator.Correlate(findings);

        // No known escalation pairs in this set (Beaconing+MacSpoofing, Beaconing+PortScan, MacSpoofing+PortScan are not pairs)
        var temporalEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.TemporalSequence).ToList();
        Assert.Equal(2, temporalEdges.Count);
        Assert.All(temporalEdges, e => Assert.Equal(CorrelationType.TemporalSequence, e.CorrelationType));
    }

    [Fact]
    public void Correlate_PostureFindingsOnSameHost_DoesNotCreateTemporalSequenceEdges()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                RuleId = "FW-001",
                Category = "Firewall",
                SourceHost = "localhost",
                Target = "firewall",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime,
                ShortDescription = "Firewall inactive"
            },
            new()
            {
                RuleId = "SSH-001",
                Category = "SSH",
                SourceHost = "localhost",
                Target = "sshd_config",
                TimeRangeStart = baseTime.AddSeconds(1),
                TimeRangeEnd = baseTime.AddSeconds(1),
                ShortDescription = "SSH root login enabled"
            },
            new()
            {
                RuleId = "LOG-001",
                Category = "Logging",
                SourceHost = "localhost",
                Target = "logging",
                TimeRangeStart = baseTime.AddSeconds(2),
                TimeRangeEnd = baseTime.AddSeconds(2),
                ShortDescription = "Logging inactive"
            }
        };

        var result = _correlator.Correlate(findings);

        Assert.DoesNotContain(result.Edges, e => e.CorrelationType == CorrelationType.TemporalSequence);
    }

    [Fact]
    public void Correlate_SameTargetDifferentCategories_CreatesSameHostEdge()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.50:22",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing"
            },
            new()
            {
                Category = FindingCategories.MacSpoofing,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.50:22",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "MAC spoof"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                SourceHost = "10.0.0.1",
                Target = "target-x",
                TimeRangeStart = baseTime.AddMinutes(20),
                TimeRangeEnd = baseTime.AddMinutes(25),
                ShortDescription = "Port scan"
            }
        };

        var result = _correlator.Correlate(findings);

        // TemporalSequence edges: Beaconing→MacSpoofing and MacSpoofing→PortScan
        var temporalEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.TemporalSequence).ToList();
        Assert.Equal(2, temporalEdges.Count);

        // SameHost edge: Beaconing and MacSpoofing share target, but already TemporalSequence → no SameHost
        var sameHostEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.SameHost).ToList();
        Assert.Empty(sameHostEdges);
    }

    [Fact]
    public void Correlate_NonConsecutiveSameTarget_CreatesSameHostEdge()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.50:22",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                SourceHost = "10.0.0.1",
                Target = "target-middle",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "Port scan"
            },
            new()
            {
                Category = FindingCategories.MacSpoofing,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.50:22",
                TimeRangeStart = baseTime.AddMinutes(20),
                TimeRangeEnd = baseTime.AddMinutes(25),
                ShortDescription = "MAC spoof"
            }
        };

        var result = _correlator.Correlate(findings);

        // Beaconing and MacSpoofing share target but are not consecutive (PortScan is in between)
        // TemporalSequence creates Beaconing→PortScan and PortScan→MacSpoofing
        // SameHost creates a direct edge between Beaconing and MacSpoofing
        var sameHostEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.SameHost).ToList();
        Assert.Single(sameHostEdges);
        Assert.Contains("192.168.1.50:22", sameHostEdges[0].Narrative);
    }

    [Fact]
    public void Correlate_NonOverlappingTimeRanges_GapWithin24h_CreatesEdge()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.FlagAnomaly,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "192.168.1.1:22",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddHours(1),
                ShortDescription = "FIN without SYN",
                Details = "Stealth scan"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "multiple hosts/ports",
                TimeRangeStart = baseTime.AddHours(3),
                TimeRangeEnd = baseTime.AddHours(4),
                ShortDescription = "Port scan detected",
                Details = "20 distinct destinations"
            }
        };

        var result = _correlator.Correlate(findings);

        Assert.Single(result.Edges);
        Assert.Contains("2.0 hours", result.Edges[0].Narrative);
        Assert.Equal(CorrelationConfidence.Medium, result.Edges[0].Confidence); // 2-hour gap
    }

    [Theory]
    [InlineData(0, CorrelationConfidence.High)]      // overlapping
    [InlineData(30, CorrelationConfidence.High)]     // 30-minute gap
    [InlineData(90, CorrelationConfidence.Medium)]   // 1.5-hour gap
    [InlineData(420, CorrelationConfidence.Low)]     // 7-hour gap
    public void Correlate_ConfidenceVariesByGap(int gapMinutes, CorrelationConfidence expected)
    {
        var baseTime = DateTime.UtcNow;
        var a = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(10),
            ShortDescription = "A"
        };
        var b = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            TimeRangeStart = baseTime.AddMinutes(10 + gapMinutes),
            TimeRangeEnd = baseTime.AddMinutes(20 + gapMinutes),
            ShortDescription = "B"
        };

        var result = _correlator.Correlate(new[] { a, b });

        Assert.Single(result.Edges);
        Assert.Equal(expected, result.Edges[0].Confidence);
    }

    [Fact]
    public void Correlate_NonOverlappingTimeRanges_GapExceeds24h_NoEdge()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddHours(1),
                ShortDescription = "Beaconing detected",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = baseTime.AddHours(26),
                TimeRangeEnd = baseTime.AddHours(27),
                ShortDescription = "Lateral movement detected",
                Details = "Contacted 5 internal hosts"
            }
        };

        var result = _correlator.Correlate(findings);

        Assert.Empty(result.Edges);
    }

    [Fact]
    public void Correlate_MultipleFindingsSamePair_CreatesMultipleEdges()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing 1",
                Details = "First"
            },
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.6:443",
                TimeRangeStart = baseTime.AddMinutes(30),
                TimeRangeEnd = baseTime.AddMinutes(35),
                ShortDescription = "Beaconing 2",
                Details = "Second"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "Lateral movement",
                Details = "Contacted 5 internal hosts"
            }
        };

        var result = _correlator.Correlate(findings);

        // Beaconing1 -> LateralMovement, Beaconing2 -> LateralMovement = 2 edges
        Assert.Equal(2, result.Edges.Count);
    }

    [Fact]
    public void Correlate_ReversedTimeOrder_EdgeDirectionIsCorrect()
    {
        var baseTime = DateTime.UtcNow;
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Lateral movement first",
            Details = "Happened before beaconing"
        };
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Beaconing second",
            Details = "Happened after lateral movement"
        };

        var result = _correlator.Correlate(new[] { lateral, beaconing });

        Assert.Single(result.Edges);
        Assert.Equal(lateral.Id, result.Edges[0].FromFindingId);
        Assert.Equal(beaconing.Id, result.Edges[0].ToFindingId);
    }

    [Fact]
    public void Correlate_DoesNotMutateFindings()
    {
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Details = "Contacted 5 internal hosts"
        };

        var result = _correlator.Correlate(new[] { beaconing, lateral });

        // Original findings should be returned unchanged
        Assert.Equal(Severity.Medium, result.Findings[0].Severity);
        Assert.Equal(Severity.High, result.Findings[1].Severity);
    }

    [Fact]
    public void Correlate_CriticalChain_BeaconingLateralMovementPrivilegeEscalation_Detected()
    {
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement detected",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation indicator",
            Details = "Detected 6 admin port access attempts"
        };

        var result = _correlator.Correlate(new[] { beaconing, lateral, privEsc });

        Assert.Single(result.CriticalChains);
        var chain = result.CriticalChains[0];
        Assert.Equal("192.168.1.100", chain.Host);
        Assert.Contains("Beaconing", chain.Narrative);
        Assert.Contains("PrivilegeEscalation", chain.Narrative);
        Assert.Equal(3, chain.FindingIds.Count);
        Assert.Equal(beaconing.Id, chain.FindingIds[0]);
        Assert.Equal(lateral.Id, chain.FindingIds[1]);
        Assert.Equal(privEsc.Id, chain.FindingIds[2]);
    }

    [Fact]
    public void Correlate_CriticalChain_C2ChannelLateralMovementPrivilegeEscalation_Detected()
    {
        // A C2Channel finding satisfies the opening stage of the critical chain just as Beaconing
        // does (regression: the trigger was Beaconing-only before C2Channel was added as an alias).
        var baseTime = DateTime.UtcNow;
        var c2 = new Finding
        {
            Category = FindingCategories.C2Channel,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "203.0.113.10:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "C2 channel detected",
            Details = "Periodic communication"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement detected",
            Details = "Contacted 5 internal hosts"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation indicator",
            Details = "Detected 6 admin port access attempts"
        };

        var result = _correlator.Correlate(new[] { c2, lateral, privEsc });

        Assert.Single(result.CriticalChains);
        var chain = result.CriticalChains[0];
        Assert.Equal("192.168.1.100", chain.Host);
        Assert.Contains("C2", chain.Narrative);
        Assert.Contains("PrivilegeEscalation", chain.Narrative);
        Assert.Equal(3, chain.FindingIds.Count);
        Assert.Equal(c2.Id, chain.FindingIds[0]);
        Assert.Equal(lateral.Id, chain.FindingIds[1]);
        Assert.Equal(privEsc.Id, chain.FindingIds[2]);
    }

    [Fact]
    public void Correlate_NoCriticalChain_MissingOneCategory_ReturnsEmpty()
    {
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected",
            Details = "Regular intervals"
        };
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement detected",
            Details = "Contacted 5 internal hosts"
        };

        var result = _correlator.Correlate(new[] { beaconing, lateral });

        Assert.Empty(result.CriticalChains);
    }

    [Fact]
    public void Correlate_CriticalChain_ShuffledInput_FindingIdsSortedByTimestamp()
    {
        var baseTime = DateTime.UtcNow;
        // Create findings with deliberate out-of-order timestamps
        var lateral = new Finding
        {
            Category = FindingCategories.LateralMovement,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime,                    // earliest
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Lateral movement first"
        };
        var privEsc = new Finding
        {
            Category = FindingCategories.PrivilegeEscalation,
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(10),    // middle
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Privilege escalation middle"
        };
        var beaconing = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime.AddMinutes(20),    // latest
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Beaconing last"
        };

        // Pass findings in random order
        var result = _correlator.Correlate(new[] { privEsc, beaconing, lateral });

        Assert.Single(result.CriticalChains);
        var chain = result.CriticalChains[0];
        // FindingIds must be sorted by timestamp regardless of input order
        Assert.Equal(lateral.Id, chain.FindingIds[0]);
        Assert.Equal(privEsc.Id, chain.FindingIds[1]);
        Assert.Equal(beaconing.Id, chain.FindingIds[2]);
    }
}
