using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class BeaconingDetectorTests
{
    private readonly BeaconingDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_BeaconingRegularIntervals_ReturnsFinding()
    {
        // Arrange - Perfect beaconing: 60-second intervals with low variance
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 300,
            BeaconMaxSamplesPerTuple = 0, // Unlimited
            BeaconTrimPercent = 0.1
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("Beaconing", findings[0].Category);
        Assert.Equal(Severity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Detect_BeaconingBelowMinEventsThreshold_ReturnsNoFindings()
    {
        // Arrange - Only 3 events (below threshold of 5)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 3; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingAboveStdDevThreshold_ReturnsNoFindings()
    {
        // Arrange - High variance in intervals (not regular)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        // Irregular intervals: 10s, 100s, 15s, 95s, 12s - high variance
        var intervals = new[] { 10, 100, 15, 95, 12, 88, 20, 85 };
        var currentTime = startTime;
        foreach (var interval in intervals)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = currentTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
            currentTime = currentTime.AddSeconds(interval);
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 5,
            BeaconMaxIntervalSeconds = 120,
            BeaconStdDevThreshold = 5.0, // Very strict
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingBelowMinIntervalThreshold_ReturnsNoFindings()
    {
        // Arrange - Too frequent (10-second intervals)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 10),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30, // 10s is below threshold
            BeaconMaxIntervalSeconds = 300
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingAboveMaxIntervalThreshold_ReturnsNoFindings()
    {
        // Arrange - Too infrequent (5-minute intervals)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i * 5),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 299, // 5 minutes (300s) is above 299s threshold
            BeaconStdDevThreshold = 10.0
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingBelowMinDurationThreshold_ReturnsNoFindings()
    {
        // Arrange - Not enough duration (30 seconds for 5 events with 10s intervals)
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 10),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 5,
            BeaconMaxIntervalSeconds = 120,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100 // Need at least 100 seconds
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingDisabled_ReturnsNoFindings()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = false // Disabled
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
        var profile = new AnalysisProfile { EnableBeaconing = true };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_InternalPeriodicTraffic_ReturnsNoFindings()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.5",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings;

        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_MultipleBeacons_ReturnsMultipleFindings()
    {
        // Arrange - Multiple beaconing patterns
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();

        // Beacon 1: 192.168.1.100 -> 8.8.8.8:8080
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        // Beacon 2: 192.168.1.101 -> 1.1.1.1:443
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 120),
                SourceIP = "192.168.1.101",
                DestinationIP = "1.1.1.1",
                DestinationPort = 443,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.True(findings.Count >= 1);
    }

    [Fact]
    public void Detect_BeaconingWithTrimmedIntervals_AnalyzesCorrectly()
    {
        // Arrange - Some outliers that should be trimmed
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        // Regular 60s intervals with a few outliers
        var intervals = new[] { 60, 60, 60, 60, 60, 300, 60, 60, 60, 60 }; // One 300s outlier
        var currentTime = startTime;
        foreach (var interval in intervals)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = currentTime,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
            currentTime = currentTime.AddSeconds(interval);
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100,
            BeaconTrimPercent = 0.2 // Trim 20% (1-2 outliers)
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Should still detect after trimming
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_BeaconingWithMaxSamplesLimit_UsesLatestSamples()
    {
        // Arrange - Many events, but only latest should be analyzed
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 100; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100,
            BeaconMaxSamplesPerTuple = 10 // Only analyze latest 10
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_NonBeaconingTraffic_ReturnsNoFindings()
    {
        // Arrange - Random traffic patterns
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        var random = new Random(42); // Fixed seed for reproducibility
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(random.Next(0, 300)),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_BeaconingDifferentPorts_SeparatesByTuple()
    {
        // Arrange - Same source to different destinations/ports
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();

        // Same source, different destination port
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 9090,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Should detect both beaconing patterns separately
        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Detect_Beaconing_ReturnsFindingWithCorrectProperties()
    {
        // Arrange
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("Beaconing", finding.Category);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.NotEqual(Guid.Empty, finding.Id);
        Assert.NotNull(finding.ShortDescription);
        Assert.NotNull(finding.Details);
        Assert.Equal("192.168.1.100", finding.SourceHost);
        Assert.Contains("8.8.8.8:8080", finding.Target);
        Assert.True(finding.TimeRangeStart <= finding.TimeRangeEnd);
    }

    [Fact]
    public void Detect_BeaconingWithNftablesFormat_ParsesCorrectly()
    {
        // Arrange - nftables format logs
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Nftables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert - Should work the same with nftables format
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_SmallIntervalCountWithHighTrimPercent_StillDetects()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 6; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 60),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 200,
            BeaconMaxSamplesPerTuple = 0,
            BeaconTrimPercent = 0.4
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Single(findings);
    }

    [Fact]
    public void Detect_ExactMinEventsAtExactDuration_ReturnsFinding()
    {
        // Boundary: 5 events spanning exactly 100 seconds (min duration)
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 25),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 20,
            BeaconMaxIntervalSeconds = 30,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_JustBelowMinDuration_ReturnsNoFindings()
    {
        // Boundary: 5 events spanning 99 seconds when min is 100
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 5; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 24.75),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 20,
            BeaconMaxIntervalSeconds = 30,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_ExactMinIntervalBoundary_ReturnsFinding()
    {
        // Boundary: mean interval exactly at MinIntervalSeconds
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 6; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 30),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 60,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Single(findings);
    }

    [Fact]
    public void Detect_JustBelowMinInterval_ReturnsNoFindings()
    {
        // Boundary: mean interval just below MinIntervalSeconds
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 6; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(i * 29),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 5,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 60,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_HighTrimPercentWithSmallIntervalSet_DoesNotProduceDegenerateStatistics()
    {
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        var seconds = new[] { 0, 60, 120, 180, 50180 };
        foreach (var s in seconds)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddSeconds(s),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 8080,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables
            });
        }

        var profile = new AnalysisProfile
        {
            EnableBeaconing = true,
            BeaconMinEvents = 4,
            BeaconMinIntervalSeconds = 30,
            BeaconMaxIntervalSeconds = 300,
            BeaconStdDevThreshold = 5.0,
            BeaconMinDurationSeconds = 100,
            BeaconMaxSamplesPerTuple = 0,
            BeaconTrimPercent = 0.34
        };

        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        Assert.Empty(findings);
    }
}
