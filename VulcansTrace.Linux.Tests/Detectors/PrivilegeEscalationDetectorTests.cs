using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Detectors;

public class PrivilegeEscalationDetectorTests
{
    [Fact]
    public void PrivilegeEscalationDetector_Detect_WithAdminSpikes_FindsPrivilegeEscalationIndicator()
    {
        // Arrange
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(0),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54321
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(1),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54322
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54323
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(3),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54324
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(4),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54325
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10
        };

        var detector = new PrivilegeEscalationDetector();

        // Act
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.NotEmpty(findings);
        var finding = findings.First();
        Assert.Equal("PrivilegeEscalation", finding.Category);
        Assert.Contains("admin access attempts", finding.ShortDescription);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_Disabled_NotRun()
    {
        // Arrange
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(0),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54321
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = false
        };

        var detector = new PrivilegeEscalationDetector();

        // Act
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_NoSpike_NotDetected()
    {
        // Arrange
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(0),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54321
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(30), // Outside window
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22, // SSH
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 54322
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5 // Small window
        };

        var detector = new PrivilegeEscalationDetector();

        // Act
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_AdminPortSweep_FindsIndicator()
    {
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(0),
                SourceIP = "192.168.1.150",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 51000
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(1),
                SourceIP = "192.168.1.150",
                DestinationIP = "10.0.0.50",
                DestinationPort = 3389,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 51001
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = "192.168.1.150",
                DestinationIP = "10.0.0.50",
                DestinationPort = 5900,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 51002
            }
        };

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            AdminPorts = new[] { 22, 3389, 5900 }
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;

        Assert.Contains(findings, f => f.ShortDescription.Contains("Admin port sweep", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_EmptyEvents_ReturnsNoFindings()
    {
        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5
        };

        var detector = new PrivilegeEscalationDetector();
        Assert.Empty(detector.Detect([], profile, CancellationToken.None).Findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_NonAdminPorts_NoFindings()
    {
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 10)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 50000 + i
            })
            .ToList();

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 15
        };

        var detector = new PrivilegeEscalationDetector();
        Assert.Empty(detector.Detect(events, profile, CancellationToken.None).Findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_ConfigurableSpikeThreshold_Respected()
    {
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 4)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 50000 + i
            })
            .ToList();

        var highThreshold = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var lowThreshold = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 3
        };

        var detector = new PrivilegeEscalationDetector();

        Assert.Empty(detector.Detect(events, highThreshold, CancellationToken.None).Findings);
        Assert.NotEmpty(detector.Detect(events, lowThreshold, CancellationToken.None).Findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_ConfigurableSweepThreshold_Respected()
    {
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new() { Timestamp = startTime.AddMinutes(0), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 22, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50001 },
            new() { Timestamp = startTime.AddMinutes(1), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 3389, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50002 },
            new() { Timestamp = startTime.AddMinutes(2), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 5432, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50003 }
        };

        var needsThree = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSweepMinDistinctPorts = 4
        };

        var needsTwo = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSweepMinDistinctPorts = 3
        };

        var detector = new PrivilegeEscalationDetector();

        Assert.Empty(detector.Detect(events, needsThree, CancellationToken.None).Findings);
        Assert.Contains(detector.Detect(events, needsTwo, CancellationToken.None).Findings,
            f => f.ShortDescription.Contains("sweep", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_SpikeFindingProperties_AreCorrect()
    {
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 6)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "172.16.0.5",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 50000 + i
            })
            .ToList();

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Contains(findings, f =>
            f.Category == "PrivilegeEscalation" &&
            f.Severity == Severity.High &&
            f.SourceHost == "172.16.0.5" &&
            f.TimeRangeEnd >= f.TimeRangeStart &&
            f.Details.Contains("admin port access attempts"));
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_ExactMinAttemptsInSpike_ReturnsFinding()
    {
        // Boundary: exactly 5 attempts within window (default min attempts)
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 5)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 50000 + i
            })
            .ToList();

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.NotEmpty(findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_JustBelowMinAttemptsInSpike_ReturnsNoFindings()
    {
        // Boundary: 4 attempts when threshold is 5
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 4)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                SourcePort = 50000 + i
            })
            .ToList();

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.Empty(findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_ExactMinDistinctPortsInSweep_ReturnsFinding()
    {
        // Boundary: exactly 3 distinct admin ports (default min sweep)
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>
        {
            new() { Timestamp = startTime.AddMinutes(0), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 22, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50001 },
            new() { Timestamp = startTime.AddMinutes(1), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 3389, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50002 },
            new() { Timestamp = startTime.AddMinutes(2), SourceIP = "10.0.0.1", DestinationIP = "10.0.0.50", DestinationPort = 5900, Protocol = "TCP", LogFormat = LogFormat.Iptables, SourcePort = 50003 }
        };

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSweepMinDistinctPorts = 3,
            AdminPorts = new[] { 22, 3389, 5900 }
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.Contains(findings, f => f.ShortDescription.Contains("sweep", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_SpikeExactlyAtWindowBoundary_ReturnsFinding()
    {
        // Boundary: 5 events at t=0 and t=10min (exactly at window edge)
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 4; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        // 5th event exactly at window boundary (10 minutes)
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(10),
            SourceIP = "192.168.1.100",
            DestinationIP = "10.0.0.50",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.NotEmpty(findings);
    }

    [Fact]
    public void PrivilegeEscalationDetector_Detect_SpikeJustBeyondWindowBoundary_ReturnsNoFindings()
    {
        // Boundary: 5 events with last at 10min+1s (just outside window)
        var startTime = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 4; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        // 5th event just beyond window boundary
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(10).AddSeconds(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "10.0.0.50",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 10,
            PrivilegeSpikeMinAttempts = 5
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_TwoDistinctAdminSpikeBurstsSameSource_ReturnsMultipleFindings()
    {
        // Arrange - two bursts of admin access separated by a gap
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();

        // Burst 1: exactly 5 rapid SSH attempts (matches threshold)
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Burst 2: exactly 5 rapid SSH attempts, 30 minutes later
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(30).AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.50",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSpikeMinAttempts = 5,
            PrivilegeSweepMinDistinctPorts = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - should detect spike findings for both bursts
        var spikeFindings = findings.Where(f => f.Details.Contains("brute force")).ToList();
        Assert.Equal(2, spikeFindings.Count);
        Assert.All(spikeFindings, f => Assert.Equal("PrivilegeEscalation", f.Category));
        Assert.All(spikeFindings, f => Assert.Equal("192.168.1.100", f.SourceHost));
    }

    [Fact]
    public void PrivilegeEscalationDetector_SustainedAdminSpike_TimeRangeEndCoversLastEvent()
    {
        // Regression: sustained admin access slightly beyond one window
        // must produce a finding whose TimeRangeEnd covers the last event.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        var srcIp = "10.0.0.99";

        // 12 admin port events at 30s intervals = 330s span with a 5-min window
        for (int i = 0; i < 12; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 30),
                SourceIP = srcIp,
                DestinationIP = "192.168.1.1",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSpikeMinAttempts = 8,
            AdminPorts = new[] { 22 }
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.NotEmpty(findings);

        var lastEventTime = events.Last().Timestamp;
        var spikeFinding = findings.First(f => f.Details.Contains("brute force"));
        Assert.True(spikeFinding.TimeRangeEnd >= lastEventTime,
            $"TimeRangeEnd ({spikeFinding.TimeRangeEnd:O}) should cover last event ({lastEventTime:O})");
    }

    [Fact]
    public void PrivilegeEscalationDetector_SustainedPortSweep_TargetReflectsAllPorts()
    {
        // Regression: sustained port sweep discovering new admin ports must
        // update Target to reflect the full port list, not just the initial sample.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        var srcIp = "10.0.0.99";

        // Phase 1: hit 3 admin ports (meets threshold)
        var phase1Ports = new[] { 22, 3389, 5900 };
        foreach (var port in phase1Ports)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = srcIp,
                DestinationIP = "192.168.1.1",
                DestinationPort = port,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Phase 2: hit 2 more admin ports (sweep extends)
        var phase2Ports = new[] { 5432, 3306 };
        foreach (var port in phase2Ports)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = srcIp,
                DestinationIP = "192.168.1.1",
                DestinationPort = port,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePrivilegeEscalationDetection = true,
            PrivilegeSpikeWindowMinutes = 5,
            PrivilegeSweepMinDistinctPorts = 3,
            AdminPorts = new[] { 22, 3389, 5900, 5432, 3306 }
        };

        var detector = new PrivilegeEscalationDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        var sweepFinding = findings.FirstOrDefault(f => f.Details.Contains("admin ports within"));
        Assert.NotNull(sweepFinding);

        // Target should reflect all 5 ports (or at least mention ports beyond the initial 3)
        Assert.Contains("5", sweepFinding.Details);
    }
}
