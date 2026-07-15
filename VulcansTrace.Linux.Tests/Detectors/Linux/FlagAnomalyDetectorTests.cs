using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Linux;

public class FlagAnomalyDetectorTests
{
    private readonly FlagAnomalyDetector _detector = new();

    [Fact]
    public void Detect_FinWithoutSyn_ReturnsFinding()
    {
        // Arrange - FIN flag without SYN (stealth scan indicator)
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
                    { "Flags", "FIN" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.FlagAnomaly, findings[0].Category);
        Assert.Equal(EngineRuleIds.FlagAnomaly, findings[0].RuleId);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Contains("FIN-without-SYN", findings[0].ShortDescription);
        Assert.Contains("stealth port scanning", findings[0].Details);
    }

    [Fact]
    public void Detect_EmptyFlags_ReturnsNoFindings()
    {
        // Arrange - TCP packet with missing flags should not trigger
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_XmasScan_ReturnsFinding()
    {
        // Arrange - XMAS scan with FIN, PSH, URG flags
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "FIN PSH URG" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - XMAS scan is categorized as XMAS only (not also FIN-without-SYN)
        Assert.Single(findings);
        Assert.Contains(findings, f => f.ShortDescription.Contains("XMAS scan"));
        Assert.All(findings, f => Assert.Equal(FindingCategories.FlagAnomaly, f.Category));
    }

    [Fact]
    public void Detect_MoreThanFiveTargets_ReportsTotalTargetCount()
    {
        var startTime = DateTime.Now;
        var events = Enumerable.Range(1, 7)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.0.{i}",
                DestinationPort = 80 + i,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "FIN" }
                }
            })
            .ToList();

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        var finding = Assert.Single(findings);
        Assert.Contains("7 target(s)", finding.Details);
        Assert.Contains("...", finding.Target);
    }

    [Fact]
    public void Detect_NormalSynPacket_ReturnsNoFindings()
    {
        // Arrange - Normal SYN packet (should not trigger)
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
                    { "Flags", "SYN" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_NormalSynAckPacket_ReturnsNoFindings()
    {
        // Arrange - Normal SYN-ACK packet (should not trigger)
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
                    { "Flags", "SYN ACK" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_UdpTraffic_ReturnsNoFindings()
    {
        // Arrange - UDP traffic (should be ignored)
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 53,
                Protocol = "UDP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "FIN" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_FlagAnomalyDisabled_ReturnsNoFindings()
    {
        // Arrange - Flag anomaly detection disabled
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
                    { "Flags", "FIN" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = false
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
        var profile = new AnalysisProfile { EnableFlagAnomaly = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleFlagAnomalies_ReturnsMultipleFindings()
    {
        // Arrange - Multiple suspicious flag combinations
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
                    { "Flags", "FIN" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddSeconds(1),
                SourceIP = "192.168.1.101",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddSeconds(2),
                SourceIP = "192.168.1.102",
                DestinationIP = "10.0.0.5",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "FIN PSH URG" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - XMAS scan produces 1 finding (not double-counted), plus FIN-without-SYN = 2 total
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(FindingCategories.FlagAnomaly, f.Category));
    }

    [Fact]
    public void Detect_FinWithSyn_ReturnsNoFindings()
    {
        // Arrange - FIN with SYN (legitimate packet, not anomaly)
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
                    { "Flags", "FIN SYN" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Should not trigger FIN without SYN detection
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_FinAck_NormalTeardown_ReturnsNoFindings()
    {
        // Arrange - FIN ACK is normal TCP teardown, not a stealth scan
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
                    { "Flags", "FIN ACK" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableFlagAnomaly = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Normal teardown should not trigger FIN-without-SYN
        Assert.Empty(findings);
    }
}
