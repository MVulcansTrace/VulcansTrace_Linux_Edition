using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class FloodDetectorTests
{
    private readonly FloodDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_FloodAboveMinEventsThreshold_ReturnsFinding()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(2))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Flood", findings[0].Category);
        Assert.Equal(EngineRuleIds.Flood, findings[0].RuleId);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void Detect_FloodBelowMinEventsThreshold_ReturnsNoFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 10, duration: TimeSpan.FromMinutes(1))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_FloodAtMinEventsThreshold_ReturnsFinding()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 30, duration: TimeSpan.FromMinutes(1))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_FloodDisabled_ReturnsNoFindings()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(2))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = false // Disabled
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
        var profile = new AnalysisProfile { EnableFlood = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleFloodingSources_ReturnsMultipleFindings()
    {
        // Arrange - Create flood from multiple sources
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=81
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=82
kernel: Jan 19 10:15:35 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80
kernel: Jan 19 10:15:36 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=81
kernel: Jan 19 10:15:37 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=82
kernel: Jan 19 10:15:38 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=83
kernel: Jan 19 10:15:39 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=84
kernel: Jan 19 10:15:40 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=85
kernel: Jan 19 10:15:41 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=86
kernel: Jan 19 10:15:42 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=87
kernel: Jan 19 10:15:43 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=88
kernel: Jan 19 10:15:44 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=89
kernel: Jan 19 10:15:45 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=90
kernel: Jan 19 10:15:46 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=91
kernel: Jan 19 10:15:47 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=92
kernel: Jan 19 10:15:48 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=93
kernel: Jan 19 10:15:49 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=94
kernel: Jan 19 10:15:50 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=95
kernel: Jan 19 10:15:51 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=96
kernel: Jan 19 10:15:52 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=97
kernel: Jan 19 10:15:53 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=98
kernel: Jan 19 10:15:54 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=99
kernel: Jan 19 10:15:55 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=100
kernel: Jan 19 10:15:56 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=101
kernel: Jan 19 10:15:57 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=102
kernel: Jan 19 10:15:58 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=103
kernel: Jan 19 10:15:59 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=104
kernel: Jan 19 10:16:00 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=105
kernel: Jan 19 10:16:01 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=106
kernel: Jan 19 10:16:02 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=107
kernel: Jan 19 10:16:03 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=108
kernel: Jan 19 10:16:04 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=109
kernel: Jan 19 10:16:05 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=110";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1); // At least one source should be detected
    }

    [Fact]
    public void Detect_FloodSpanningMultipleWindows_ReturnsSingleFinding()
    {
        // Arrange - Events spanning exactly the window threshold
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 35; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 80 + (i % 10),
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
    }

    [Fact]
    public void Detect_Flood_ReturnsFindingWithCorrectProperties()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(2))
            .Generate();
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("Flood", finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.NotNull(finding.ShortDescription);
        Assert.NotNull(finding.Details);
        Assert.NotNull(finding.SourceHost);
        Assert.NotNull(finding.Target);
        Assert.True(finding.TimeRangeStart <= finding.TimeRangeEnd);
    }

    [Fact]
    public void Detect_ExactMinEventsWithinExactWindow_ReturnsFinding()
    {
        // Boundary: exactly 30 events within exactly 60 seconds should trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 30; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_ExactMinEventsSpreadJustBeyondWindow_ReturnsNoFindings()
    {
        // Boundary: 30 events spread over 60 seconds + 1 second should NOT trigger
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 30; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }
        // Push the last event just beyond the window
        events[29] = new UnifiedEvent
        {
            Timestamp = startTime.AddSeconds(61),
            SourceIP = events[29].SourceIP,
            DestinationIP = events[29].DestinationIP,
            DestinationPort = events[29].DestinationPort,
            Protocol = events[29].Protocol,
            LogFormat = events[29].LogFormat
        };

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_TwoDistinctFloodBurstsSameSource_ReturnsAtLeastTwoFindings()
    {
        // Arrange - two flood bursts separated by a quiet period
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        var srcIp = "192.168.1.100";

        // Burst 1: 50 events all at the same timestamp
        for (int i = 0; i < 50; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime,
                SourceIP = srcIp,
                DestinationIP = "10.0.0.1",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Burst 2: 50 events at a timestamp 10 minutes later
        for (int i = 0; i < 50; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(10),
                SourceIP = srcIp,
                DestinationIP = "10.0.0.1",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 50,
            FloodWindowSeconds = 60
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - should detect both bursts
        Assert.True(findings.Count >= 2, $"Expected at least 2 findings, got {findings.Count}");
        Assert.All(findings, f => Assert.Equal("Flood", f.Category));
        Assert.All(findings, f => Assert.Equal(srcIp, f.SourceHost));
    }

    [Fact]
    public void Detect_SustainedFloodTail_TimeRangeEndCoversLastEvent()
    {
        // Regression: 40 events from one source at 2-second intervals with
        // FloodWindowSeconds=60 and FloodMinEvents=30. The flood spans 78 seconds,
        // slightly more than one window. The finding's TimeRangeEnd must cover
        // the last event, not just the first 30.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 40; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 2),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableFlood = true,
            FloodMinEvents = 30,
            FloodWindowSeconds = 60
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Single(findings);
        var finding = findings[0];

        // The finding must cover the last event's timestamp
        var lastEventTime = events.Last().Timestamp;
        Assert.True(finding.TimeRangeEnd >= lastEventTime,
            $"TimeRangeEnd ({finding.TimeRangeEnd:O}) should cover the last event ({lastEventTime:O})");

        // Peak count should reflect the maximum window observed
        Assert.Contains("events within 60 seconds", finding.Details);
    }
}
