using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Linux;

public class UnusualPacketSizeDetectorTests
{
    private readonly UnusualPacketSizeDetector _detector = new();

    [Fact]
    public void Detect_UnusuallyLargePacket_ReturnsFinding()
    {
        // Arrange - Packet larger than 3000 bytes
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
                    { "Length", "5000" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.UnusualPacketSize, findings[0].Category);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("unusually large packet", findings[0].ShortDescription);
        Assert.Contains("5000", findings[0].Details);
        Assert.Contains("data exfiltration", findings[0].Details);
    }

    [Fact]
    public void Detect_UnusuallySmallPacket_ReturnsFinding()
    {
        // Arrange - Packet smaller than 40 bytes
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
                    { "Length", "20" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.UnusualPacketSize, findings[0].Category);
        Assert.Equal(Severity.Low, findings[0].Severity);
        Assert.Contains("unusually small packet", findings[0].ShortDescription);
        Assert.Contains("covert channel", findings[0].Details);
    }

    [Fact]
    public void Detect_StandardPacketSize_ReturnsNoFindings()
    {
        // Arrange - Standard packet size (1500 bytes)
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
                    { "Length", "1500" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ConsistentPacketSizes_ReturnsFinding()
    {
        // Arrange - 15 packets all the same size (75% consistency threshold)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 15; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "512" }
                }
            });
        }

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.UnusualPacketSize, findings[0].Category);
        Assert.Equal(Severity.Medium, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("Highly consistent packet sizes detected", findings[0].ShortDescription);
        Assert.Contains("100.0%", findings[0].Details);
        Assert.Contains("512 bytes", findings[0].Details);
    }

    [Fact]
    public void Detect_ConsistentPacketSizesAtExactThresholds_ReturnsFinding()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "512" }
                }
            });
        }

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true,
            PacketSizeMinForAnalysis = 10,
            PacketSizeConsistencyPercent = 100,
            PacketSizeMinConsistentCount = 10
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        var finding = Assert.Single(findings);
        Assert.Equal(FindingCategories.UnusualPacketSize, finding.Category);
        Assert.Contains("Highly consistent packet sizes detected", finding.ShortDescription);
    }

    [Fact]
    public void Detect_HighPacketSizeVariance_ReturnsFinding()
    {
        // Arrange - Mix of very large and very small packets with high variance
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
                    { "Length", "100" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(1),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "200" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "300" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(3),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "400" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(4),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "500" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(5),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "600" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(6),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "700" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(7),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "800" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(8),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "900" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(9),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "1000" }
                }
            },
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
                    { "Length", "1100" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Should detect high variance
        Assert.Contains(findings, f => f.Target.Contains("10.0.0.5:80") && f.ShortDescription.Contains("variance"));
    }

    [Fact]
    public void Detect_UnusualPacketSizeDisabled_ReturnsNoFindings()
    {
        // Arrange - Unusual packet size detection disabled
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
                    { "Length", "5000" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = false
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
        var profile = new AnalysisProfile { EnableUnusualPacketSize = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MissingLengthField_ReturnsNoFindings()
    {
        // Arrange - Event without Length field
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
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_InvalidLengthField_ReturnsNoFindings()
    {
        // Arrange - Event with non-numeric length
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
                    { "Length", "invalid" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ExactlyAtLargeThreshold_ReturnsNoFindings()
    {
        // Arrange - Exactly 3000 bytes (threshold is > 3000)
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
                    { "Length", "3000" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ZeroPacket_ReturnsNoFindings()
    {
        // Arrange - Zero-byte packet (excluded by check: length > 0 && length < 40)
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
                    { "Length", "0" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Zero packets are excluded by the check (length > 0)
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleAnomalies_ReturnsMultipleFindings()
    {
        // Arrange - Multiple packet size anomalies
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
                    { "Length", "5000" }
                }
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddSeconds(1),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Length", "10" }
                }
            }
        };

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal(FindingCategories.UnusualPacketSize, f.Category));
    }

    [Fact]
    public void Detect_MultiSourceConsistency_NoGlobalFalsePositive()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();

        for (int i = 0; i < 12; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string> { { "Length", "60" } }
            });
        }

        for (int i = 0; i < 8; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(12 + i),
                SourceIP = "192.168.2.50",
                DestinationIP = "10.0.0.6",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string> { { "Length", "1500" } }
            });
        }

        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true,
            PacketSizeMinForAnalysis = 5,
            PacketSizeConsistencyPercent = 60,
            PacketSizeMinConsistentCount = 5
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        var consistencyFindings = findings.Where(f => f.ShortDescription.Contains("consistent")).ToList();
        Assert.Equal(2, consistencyFindings.Count);
        Assert.Contains(consistencyFindings, f => f.SourceHost == "192.168.1.100" && f.Target.Contains("10.0.0.5:80"));
        Assert.Contains(consistencyFindings, f => f.SourceHost == "192.168.2.50" && f.Target.Contains("10.0.0.6:443"));
    }

    [Fact]
    public void Detect_ConsistencyByTuple_ReferencesSpecificSourceAndTarget()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 15; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.200",
                DestinationIP = "10.0.0.10",
                DestinationPort = 22,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string> { { "Length", "256" } }
            });
        }

        var profile = new AnalysisProfile { EnableUnusualPacketSize = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        var consistency = findings.FirstOrDefault(f => f.ShortDescription.Contains("consistent"));
        Assert.NotNull(consistency);
        Assert.Equal("192.168.1.200", consistency.SourceHost);
        Assert.Equal("10.0.0.10:22", consistency.Target);
    }
}
