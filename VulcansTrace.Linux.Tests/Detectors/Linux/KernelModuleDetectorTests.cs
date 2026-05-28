using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Linux;

public class KernelModuleDetectorTests
{
    private readonly KernelModuleDetector _detector = new();

    [Fact]
    public void Detect_ConntrackModule_ReturnsFinding()
    {
        // Arrange - Log line with conntrack reference
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
                RawLine = "kernel: iptables: CT 12345 match",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("KernelModule", findings[0].Category);
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Equal("Firewall Configuration", findings[0].SourceHost);
        Assert.Contains("Connection Tracking", findings[0].Target);
        Assert.Contains("Detected Connection Tracking", findings[0].ShortDescription);
        Assert.Contains("conntrack", findings[0].Details);
    }

    [Fact]
    public void Detect_RateLimitingModule_ReturnsFinding()
    {
        // Arrange - Log line with rate limiting (without hashlimit to avoid triggering quota)
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
                RawLine = "kernel: iptables: limit rate match",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("KernelModule", findings[0].Category);
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Contains("Rate Limiting", findings[0].Target);
        Assert.Contains("Analysis of firewall logs indicates the use of Rate Limiting", findings[0].Details);
    }

    [Fact]
    public void Detect_Ipv6Support_ReturnsFinding()
    {
        // Arrange - IPv6 addresses
        var events = new List<UnifiedEvent>
        {
            new UnifiedEvent
            {
                Timestamp = DateTime.Now,
                SourceIP = "2001:db8::1",
                DestinationIP = "2001:db8::2",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("KernelModule", findings[0].Category);
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Contains("IPv6 Support", findings[0].Target);
        Assert.Contains("Analysis of firewall logs indicates the use of IPv6 Support", findings[0].Details);
    }

    [Fact]
    public void Detect_Layer7Filtering_ReturnsFinding()
    {
        // Arrange - Layer 7 filtering
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
                RawLine = "kernel: iptables: layer7 match http",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("KernelModule", findings[0].Category);
        Assert.Equal(Severity.Info, findings[0].Severity);
        Assert.Contains("Layer 7 Filtering", findings[0].Target);
    }

    [Fact]
    public void Detect_QuotaModule_ReturnsFinding()
    {
        // Arrange - Quota/bandwidth limiting
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
                RawLine = "kernel: iptables: quota exceeded",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("KernelModule", findings[0].Category);
        Assert.Contains("Quota", findings[0].Target);
    }

    [Fact]
    public void Detect_HashlimitModule_ReturnsFinding()
    {
        // Arrange - Hashlimit module (triggers both rate and quota detection)
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
                RawLine = "kernel: iptables: hashlimit match",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - hashlimit triggers quota detection only
        // (word-boundary matching no longer matches "limit" inside "hashlimit")
        Assert.Single(findings);
        Assert.Contains(findings, f => f.Target.Contains("Quota"));
        Assert.All(findings, f => Assert.Equal("KernelModule", f.Category));
    }

    [Fact]
    public void Detect_MultipleModules_ReturnsMultipleFindings()
    {
        // Arrange - Multiple module indicators
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
                RawLine = "kernel: iptables: CT limit rate",
                LinuxSpecific = new Dictionary<string, string>()
            },
            new UnifiedEvent
            {
                Timestamp = DateTime.Now.AddSeconds(1),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                RawLine = "kernel: iptables: layer7 match https",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 2);
        Assert.Contains(findings, f => f.Target.Contains("Connection Tracking"));
        Assert.Contains(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_KernelModuleDisabled_ReturnsNoFindings()
    {
        // Arrange - Kernel module detection disabled
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
                RawLine = "kernel: iptables: CT conntrack",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = false
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
        var profile = new AnalysisProfile { EnableKernelModule = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_NoModuleIndicators_ReturnsNoFindings()
    {
        // Arrange - Standard log without module indicators
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
                RawLine = "kernel: iptables: ACCEPT tcp",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_KernelModule_ReturnsFindingWithCorrectTimeRange()
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
                RawLine = "kernel: iptables: CT conntrack",
                LinuxSpecific = new Dictionary<string, string>()
            },
            new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(5),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                RawLine = "kernel: iptables: CT conntrack",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile
        {
            EnableKernelModule = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(startTime, findings[0].TimeRangeStart);
        Assert.Equal(startTime.AddMinutes(5), findings[0].TimeRangeEnd);
    }

    [Fact]
    public void Detect_SubstringUnlimited_DoesNotTriggerRateLimiting()
    {
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
                RawLine = "kernel: iptables: unlimited traffic SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_SubstringTolerate_DoesNotTriggerRateLimiting()
    {
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
                RawLine = "kernel: iptables: tolerate connections SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_SubstringEliminate_DoesNotTriggerRateLimiting()
    {
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
                RawLine = "kernel: iptables: eliminate noise SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_WordBoundaryLimitColon_ProducesFinding()
    {
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
                RawLine = "kernel: iptables: limit: 10/minute SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Contains(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_WordBoundaryRateSpace_ProducesFinding()
    {
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
                RawLine = "kernel: iptables: rate 10/second burst 20 SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Contains(findings, f => f.Target.Contains("Rate Limiting"));
    }

    [Fact]
    public void Detect_SubstringQuotaInWord_DoesNotTriggerQuotaFinding()
    {
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
                RawLine = "kernel: iptables: overquota exceeded SRC=192.168.1.100",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Quota"));
    }

    [Theory]
    [InlineData("LIMIT", "Rate Limiting")]
    [InlineData("RATE", "Rate Limiting")]
    [InlineData("CT", "Connection Tracking")]
    [InlineData("L7", "Layer 7 Filtering")]
    [InlineData("QUOTA", "Quota")]
    public void Detect_UppercaseTokenVariants_DetectedSameAsLowercase(string token, string expectedTarget)
    {
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
                RawLine = $"kernel: iptables: {token} match",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Contains(findings, f => f.Target.Contains(expectedTarget));
    }

    [Fact]
    public void Detect_SubstringConntrackInLargerWord_DoesNotTriggerConntrackFinding()
    {
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
                RawLine = "kernel: iptables: ACCEPT SRC=192.168.1.100 PROTO=TCP note=conntrack2enabled",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Connection Tracking"));
    }

    [Fact]
    public void Detect_SubstringLayer7InPath_DoesNotTriggerLayer7Finding()
    {
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
                RawLine = "kernel: iptables: ACCEPT SRC=192.168.1.100 layer7proxy PROTO=TCP",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Layer 7"));
    }

    [Fact]
    public void Detect_SubstringHashlimitInWord_DoesNotTriggerQuotaFinding()
    {
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
                RawLine = "kernel: iptables: ACCEPT SRC=192.168.1.100 myhashlimit PROTO=TCP",
                LinuxSpecific = new Dictionary<string, string>()
            }
        };

        var profile = new AnalysisProfile { EnableKernelModule = true };
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.DoesNotContain(findings, f => f.Target.Contains("Quota"));
    }
}
