using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Linux;

public class MacSpoofingDetectorTests
{
    private readonly MacSpoofingDetector _detector = new();

    [Fact]
    public void Detect_MultipleMacAddressesForSameIp_ReturnsFinding()
    {
        // Arrange - Same IP with different MAC addresses (MAC spoofing indicator)
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100", // Same IP
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" } // Different MAC
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(20),
                SourceIP = "192.168.1.100", // Same IP
                DestinationIP = "10.0.0.6",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:77" } // Different MAC
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("MacSpoofing", findings[0].Category);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Equal("multiple MAC addresses", findings[0].Target);
        Assert.Contains("MAC spoofing", findings[0].ShortDescription);
        Assert.Contains("00:11:22:33:44:55", findings[0].Details);
        Assert.Contains("00:11:22:33:44:66", findings[0].Details);
        Assert.Contains("00:11:22:33:44:77", findings[0].Details);
    }

    [Fact]
    public void Detect_SingleMacAddressPerIp_ReturnsNoFindings()
    {
        // Arrange - Each IP has only one MAC address (normal behavior)
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddSeconds(10),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_FullEthernetTuplesWithSameSourceMac_ReturnsNoFindings()
    {
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
                    { "MAC", "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.6",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "11:22:33:44:55:66:00:11:22:33:44:55:08:00" }
                }
            }
        };

        var profile = new AnalysisProfile { EnableMacSpoofing = true };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_FullEthernetTuplesWithDifferentSourceMacs_ReturnsFinding()
    {
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
                    { "MAC", "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.6",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "aa:bb:cc:dd:ee:ff:00:11:22:33:44:66:08:00" }
                }
            }
        };

        var profile = new AnalysisProfile { EnableMacSpoofing = true };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Single(findings);
        Assert.Contains("00:11:22:33:44:55", findings[0].Details);
        Assert.Contains("00:11:22:33:44:66", findings[0].Details);
    }

    [Fact]
    public void Detect_DifferentMacsOutsideWindow_ReturnsNoFindings()
    {
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(30),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.6",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true,
            MacSpoofingWindowMinutes = 5
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MacSpoofingDisabled_ReturnsNoFindings()
    {
        // Arrange - MAC spoofing detection disabled
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = false
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
        var profile = new AnalysisProfile { EnableMacSpoofing = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MissingMacField_ReturnsNoFindings()
    {
        // Arrange - Events without MAC address field
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
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_EmptyMacField_ReturnsNoFindings()
    {
        // Arrange - Events with empty MAC field
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
                    { "MAC", "" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleSourcesWithMacSpoofing_ReturnsMultipleFindings()
    {
        // Arrange - Multiple IPs each with MAC spoofing
        var startTime = DateTime.Now;

        // Source 1 with multiple MACs
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(5),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            },
            // Source 2 with multiple MACs
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "aa:bb:cc:dd:ee:ff" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(15),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 3389,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "aa:bb:cc:dd:ee:00" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("MacSpoofing", f.Category));
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.100");
        Assert.Contains(findings, f => f.SourceHost == "192.168.1.101");
    }

    [Fact]
    public void Detect_MacSpoofing_ReturnsFindingWithCorrectTimeRange()
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(5), // 5 minutes later
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(startTime, findings[0].TimeRangeStart);
        Assert.Equal(startTime.AddMinutes(5), findings[0].TimeRangeEnd);
        Assert.True(findings[0].TimeRangeStart <= findings[0].TimeRangeEnd);
    }

    [Fact]
    public void Detect_MixedTrafficWithMacSpoofing_IsolatesCorrectly()
    {
        // Arrange - Mix of normal and spoofed traffic
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>
        {
            // Normal traffic - single MAC per IP
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
                    { "MAC", "11:22:33:44:55:66" }
                }
            },
            // Spoofed traffic
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(20),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            },
            // More normal traffic
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(30),
                SourceIP = "192.168.1.51",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "11:22:33:44:55:77" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("MAC spoofing", findings[0].ShortDescription);
    }

    [Fact]
    public void Detect_MacSpoofing_ReturnsFindingWithCorrectProperties()
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
                    { "MAC", "00:11:22:33:44:55" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(10),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "MAC", "00:11:22:33:44:66" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableMacSpoofing = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("MacSpoofing", finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.NotNull(finding.ShortDescription);
        Assert.NotNull(finding.Details);
        Assert.Equal("192.168.1.100", finding.SourceHost);
        Assert.Equal("multiple MAC addresses", finding.Target);
        Assert.True(finding.TimeRangeStart <= finding.TimeRangeEnd);
    }
}
