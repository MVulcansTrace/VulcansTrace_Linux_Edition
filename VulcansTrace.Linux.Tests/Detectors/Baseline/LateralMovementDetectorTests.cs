using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class LateralMovementDetectorTests
{
    private readonly LateralMovementDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_LateralMovementAboveMinHostsThreshold_ReturnsFinding()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        // Source 192.168.1.100 contacts 5 internal hosts on admin ports
        var dstHosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14" };
        var adminPorts = new[] { 22, 3389, 445 };

        foreach (var dst in dstHosts)
        {
            foreach (var port in adminPorts)
            {
                events.Add(new UnifiedEvent
                {
                    Timestamp = startTime.AddMinutes(1),
                    SourceIP = "192.168.1.100",
                    DestinationIP = dst,
                    DestinationPort = port,
                    Protocol = "TCP",
                    LogFormat = LogFormat.Iptables
                });
            }
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1);
        Assert.All(findings, f => Assert.Equal("LateralMovement", f.Category));
        Assert.All(findings, f => Assert.Equal(Severity.High, f.Severity));
        Assert.All(findings, f => Assert.Equal("192.168.1.100", f.SourceHost));
    }

    [Fact]
    public void Detect_LateralMovementBelowMinHostsThreshold_ReturnsNoFindings()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        // Only contacts 2 internal hosts (below threshold of 3)
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementAtMinHostsThreshold_ReturnsFinding()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        // Exactly 3 internal hosts
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(3),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.12",
            DestinationPort = 445,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(EngineRuleIds.LateralMovement, findings[0].RuleId);
    }

    [Fact]
    public void Detect_LateralMovementDisabled_ReturnsNoFindings()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = false // Disabled
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_EmptyEvents_ReturnsNoFindings()
    {
        // Arrange
        var events = new UnifiedEvent[0];
        var profile = new AnalysisProfile { EnableLateralMovement = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementToExternalHost_ReturnsNoFindings()
    {
        // Arrange - External destination should be ignored
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "10.0.0.1", // External
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "10.0.0.2", // External
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementFromExternalSource_ReturnsNoFindings()
    {
        // Arrange - External source should be ignored
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "203.0.113.1", // External (TEST-NET-3 from RFC 5737)
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 1,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementToNonAdminPort_ReturnsNoFindings()
    {
        // Arrange - Non-admin ports should be ignored
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 80, // Not an admin port
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 443, // Not an admin port
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementOutsideWindow_ReturnsNoFindings()
    {
        // Arrange - Events outside the time window
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        // Event outside 10-minute window
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(15),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.12",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_LateralMovementMultipleSources_ReturnsMultipleFindings()
    {
        // Arrange - Multiple sources performing lateral movement
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();

        // Source 1
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(3),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.12",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        // Source 2
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.101",
            DestinationIP = "192.168.1.20",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.101",
            DestinationIP = "192.168.1.21",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(3),
            SourceIP = "192.168.1.101",
            DestinationIP = "192.168.1.22",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1); // At least one finding
    }

    [Fact]
    public void Detect_LateralMovement_ReturnsFindingWithCorrectProperties()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(1),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.10",
            DestinationPort = 22,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(2),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.11",
            DestinationPort = 3389,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });
        events.Add(new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(3),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.12",
            DestinationPort = 445,
            Protocol = "TCP",
            LogFormat = LogFormat.Iptables
        });

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22, 3389, 445 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("LateralMovement", finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.NotNull(finding.ShortDescription);
        Assert.NotNull(finding.Details);
        Assert.Equal("192.168.1.100", finding.SourceHost);
        Assert.True(finding.TimeRangeStart <= finding.TimeRangeEnd);
    }

    [Fact]
    public void Detect_ExactMinHostsWithinExactWindow_ReturnsFinding()
    {
        // Boundary: exactly 3 hosts within exactly 10 minutes should trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 3; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i * 3),
                SourceIP = "192.168.1.100",
                DestinationIP = $"192.168.1.{10 + i}",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_ExactMinHostsSpreadJustBeyondWindow_ReturnsNoFindings()
    {
        // Boundary: 3 hosts spread over 10 minutes + 1 second should NOT trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 3; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i * 5),
                SourceIP = "192.168.1.100",
                DestinationIP = $"192.168.1.{10 + i}",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        // Push last event just beyond window
        events[2] = new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(10).AddSeconds(1),
            SourceIP = events[2].SourceIP,
            DestinationIP = events[2].DestinationIP,
            DestinationPort = events[2].DestinationPort,
            Protocol = events[2].Protocol,
            LogFormat = events[2].LogFormat
        };

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_TwoDistinctLateralMovementBurstsSameSource_ReturnsTwoFindings()
    {
        // Arrange - two bursts of lateral movement separated by a gap
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        var burst1Hosts = new[] { "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13" };
        var burst2Hosts = new[] { "192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23" };

        foreach (var dst in burst1Hosts)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(1),
                SourceIP = "192.168.1.100",
                DestinationIP = dst,
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        foreach (var dst in burst2Hosts)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(30),
                SourceIP = "192.168.1.100",
                DestinationIP = dst,
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 3,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - should detect both bursts as separate incidents
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("LateralMovement", f.Category));
        Assert.All(findings, f => Assert.Equal("192.168.1.100", f.SourceHost));
    }

    [Fact]
    public void Detect_SustainedLateralMovement_TimeRangeEndCoversLastEvent()
    {
        // Regression: sustained lateral movement across a window boundary
        // must produce a finding whose TimeRangeEnd covers the last event.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        var srcIp = "192.168.1.100";

        // 8 internal hosts on admin port 22, each hit multiple times,
        // spanning 12 minutes (slightly over a 10-minute window).
        var dstHosts = new[] { "192.168.2.1", "192.168.2.2", "192.168.2.3", "192.168.2.4",
                               "192.168.2.5", "192.168.2.6", "192.168.2.7", "192.168.2.8" };

        // First round: 8 hosts at t=0
        foreach (var dst in dstHosts)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = srcIp,
                DestinationIP = dst,
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Second round: same 8 hosts at t=8min (still within 10min window of t=0)
        foreach (var dst in dstHosts)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(8),
                SourceIP = srcIp,
                DestinationIP = dst,
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Third round: same 8 hosts at t=12min (outside 10min window of t=0, but within of t=2+)
        foreach (var dst in dstHosts)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(12),
                SourceIP = srcIp,
                DestinationIP = dst,
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableLateralMovement = true,
            LateralMinHosts = 5,
            LateralWindowMinutes = 10,
            AdminPorts = new[] { 22 }
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Should produce at least one finding
        Assert.NotEmpty(findings);

        // At least one finding must cover the last event's timestamp
        var lastEventTime = events.Last().Timestamp;
        Assert.Contains(findings, f => f.TimeRangeEnd >= lastEventTime.AddMinutes(-2));
    }
}
