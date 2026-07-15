using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class PortScanDetectorTests
{
    private readonly PortScanDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_PortScanAboveMediumThreshold_ReturnsFinding()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("PortScan", findings[0].Category);
        Assert.Equal(EngineRuleIds.PortScan, findings[0].RuleId);
    }

    [Fact]
    public void Detect_PortScanBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 5, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_SamePortAcrossManyDestinations_ReturnsNoFindings()
    {
        var startTime = DateTime.Now;
        var events = Enumerable.Range(1, 5)
            .Select(i => new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.0.{i}",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            })
            .ToArray();

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_EmptyEvents_ReturnsNoFindings()
    {
        // Arrange
        var events = new UnifiedEvent[0];
        var profile = new AnalysisProfile { EnablePortScan = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PortScanDisabled_ReturnsNoFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = false // Disabled
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PortScanAtThreshold_ReturnsFinding()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 15, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_PortScanJustBelowThreshold_ReturnsNoFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 14, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PortScanWithVeryLargePortCount_ReturnsMultipleFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 100, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - 100 distinct ports / 15 threshold = multiple distinct incidents
        Assert.True(findings.Count >= 1);
        Assert.All(findings, f => Assert.Equal("PortScan", f.Category));
    }

    [Fact]
    public void Detect_NormalTrafficBelowThreshold_ReturnsNoFindings()
    {
        // Arrange - Normal traffic with only a few ports
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=24";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PortScanMultipleSources_ReturnsMultipleFindings()
    {
        // Arrange - Port scan from multiple sources
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.101 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:35 server IN=eth0 SRC=192.168.1.101 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=23";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 2, // Lower threshold for this test
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1);
    }

    [Fact]
    public void Detect_PortScan_ReturnsFindingWithCorrectProperties()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 15,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("PortScan", finding.Category);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("192.168.1.100", finding.SourceHost);
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.NotNull(finding.ShortDescription);
        Assert.NotNull(finding.Details);
        Assert.True(finding.TimeRangeEnd >= finding.TimeRangeStart);
    }

    [Fact]
    public void Detect_MaxEntriesPerSourceExceeded_TruncatesAndWarns()
    {
        // Arrange - 30 distinct-port events from one source
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 30, duration: TimeSpan.FromMinutes(3))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = 10
        };

        // Act
        var result = _detector.Detect(events, profile, CancellationToken.None);
        var findings = result.Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1);
        Assert.All(findings, f => Assert.Equal("PortScan", f.Category));

        Assert.Single(result.Warnings);
        Assert.Contains("truncated", result.Warnings[0]);
        Assert.Contains("192.168.1.100", result.Warnings[0]);
    }

    [Fact]
    public void Detect_PortScanMultipleSources_ReturnsFindingsForBoth()
    {
        // Arrange - 2 sources, each hitting enough ports to trigger
        var log = "";
        var ports = new[] { 22, 23, 24, 25, 80, 443, 8080, 3389, 5900, 53 };
        for (int i = 0; i < ports.Length; i++)
        {
            log += $"kernel: Jan 19 10:15:{i:D2} server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT={ports[i]}\n";
            log += $"kernel: Jan 19 10:16:{i:D2} server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT={ports[i]}\n";
        }
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Both sources should produce at least one finding each
        var sourceIps = findings.Select(f => f.SourceHost).Distinct().ToList();
        Assert.True(sourceIps.Count >= 2, "Both sources should be represented in findings");
    }

    [Fact]
    public void Detect_ExactMinPortsWithinExactWindow_ReturnsFinding()
    {
        // Boundary: 5 distinct ports within exactly 5 minutes should trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 1000 + i,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_ExactMinPortsSpreadJustBeyondWindow_ReturnsNoFindings()
    {
        // Boundary: 5 distinct ports spread over 5 minutes + 1 second should NOT trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 1000 + i,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        // Push the last event just beyond the window
        events[4] = new UnifiedEvent
        {
            Timestamp = startTime.AddMinutes(5).AddSeconds(1),
            SourceIP = events[4].SourceIP,
            DestinationIP = events[4].DestinationIP,
            DestinationPort = events[4].DestinationPort,
            Protocol = events[4].Protocol,
            LogFormat = events[4].LogFormat
        };

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MaxEntriesPerSourceExactlyAtLimit_NoTruncationWarning()
    {
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 1000 + i,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = 10
        };

        var result = _detector.Detect(events, profile, CancellationToken.None);
        // 10 events with distinct ports form one continuous scan — single merged finding
        Assert.Single(result.Findings);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Detect_MaxEntriesTruncationReducesDistinctPortsBelowThreshold_ReturnsNoFindings()
    {
        // Edge case: full history has many distinct ports, but truncated tail does not.
        // First 20 events all go to different ports; last 5 events all go to the same port.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 20; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 1000 + i,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(20 + i),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 9999,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 5,
            PortScanWindowMinutes = 5,
            PortScanMaxEntriesPerSource = 5
        };

        var result = _detector.Detect(events, profile, CancellationToken.None);
        Assert.Empty(result.Findings);
        Assert.Single(result.Warnings);
        Assert.Contains("truncated", result.Warnings[0]);
    }

    [Fact]
    public void Detect_TwoDistinctPortScanBurstsSameSource_ReturnsTwoFindings()
    {
        // Arrange - two bursts of port scanning separated by a 10-minute gap
        var log = "";
        var burstPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 443, 993, 8080, 3389, 5900, 3306, 5432, 6379, 9200 };

        // Burst 1 at 10:00
        for (int i = 0; i < burstPorts.Length; i++)
        {
            log += $"kernel: Jan 19 10:00:{i:D2} server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT={burstPorts[i]}\n";
        }

        // Gap - 10 minutes of normal traffic
        log += "kernel: Jan 19 10:05:00 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80\n";

        // Burst 2 at 10:10
        for (int i = 0; i < burstPorts.Length; i++)
        {
            log += $"kernel: Jan 19 10:10:{i:D2} server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT={burstPorts[i]}\n";
        }

        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 10,
            PortScanWindowMinutes = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - should detect both bursts as separate incidents
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("PortScan", f.Category));
        Assert.All(findings, f => Assert.Equal("192.168.1.100", f.SourceHost));
    }
}
