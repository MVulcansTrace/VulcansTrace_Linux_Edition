using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Linux;

public class InterfaceHoppingDetectorTests
{
    private readonly InterfaceHoppingDetector _detector = new();

    [Fact]
    public void Detect_RapidInterfaceSwitching_ReturnsFinding()
    {
        // Arrange - Same IP switching between interfaces within 5 minutes
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2), // Within 5-minute window
                SourceIP = "192.168.1.100", // Same IP
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" } // Different interface
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(4), // Still within window
                SourceIP = "192.168.1.100", // Same IP
                DestinationIP = "10.0.0.6",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth2" } // Another interface
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("InterfaceHopping", findings[0].Category);
        Assert.Equal(EngineRuleIds.InterfaceHopping, findings[0].RuleId);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("Interface hopping", findings[0].ShortDescription);
        Assert.Contains("eth0", findings[0].Details);
        Assert.Contains("eth1", findings[0].Details);
        Assert.Contains("eth2", findings[0].Details);
    }

    [Fact]
    public void Detect_SingleInterfacePerIp_ReturnsNoFindings()
    {
        // Arrange - Each IP uses only one interface (normal behavior)
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddMinutes(1),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_InterfaceHoppingOutsideWindow_ReturnsNoFindings()
    {
        // Arrange - Interface switching but outside 5-minute window
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(6), // Outside 5-minute window
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_InterfaceHoppingDisabled_ReturnsNoFindings()
    {
        // Arrange - Interface hopping detection disabled
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = false
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
        var profile = new AnalysisProfile { EnableInterfaceHopping = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MissingInterfaceField_ReturnsNoFindings()
    {
        // Arrange - Events without InterfaceIn field
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_EmptyInterfaceField_ReturnsNoFindings()
    {
        // Arrange - Events with empty InterfaceIn field
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleSourcesWithInterfaceHopping_ReturnsMultipleFindings()
    {
        // Arrange - Multiple IPs each with interface hopping
        var startTime = DateTime.Now;

        // Source 1 hopping interfaces
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            },
            // Source 2 hopping interfaces
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(1),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth2" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(3),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 3389,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth3" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("InterfaceHopping", f.Category));
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.100");
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.101");
    }

    [Fact]
    public void Detect_InterfaceHopping_ReturnsFindingWithCorrectTimeRange()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(4),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(startTime, findings[0].TimeRangeStart);
        Assert.Equal(startTime.AddMinutes(4), findings[0].TimeRangeEnd);
        Assert.True(findings[0].TimeRangeStart <= findings[0].TimeRangeEnd);
    }

    [Fact]
    public void Detect_MixedTrafficWithInterfaceHopping_IsolatesCorrectly()
    {
        // Arrange - Mix of normal and hopping traffic
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            // Normal traffic - single interface per IP
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.50",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            // Hopping traffic
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(1),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(3),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            },
            // More normal traffic
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(2),
                SourceIP = "192.168.1.51",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth2" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("Interface hopping", findings[0].ShortDescription);
    }

    [Fact]
    public void Detect_TwoInterfaces_ReturnsFinding()
    {
        // Arrange - Just two interfaces (minimum for detection)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth0" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(3),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "InterfaceIn", "eth1" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableInterfaceHopping = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("2 network interfaces", findings[0].Target);
    }
}
