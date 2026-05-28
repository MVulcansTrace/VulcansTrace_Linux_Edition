using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Integration;

/// <summary>
/// Integration tests for SentryAnalyzer - the main orchestration engine.
/// Tests the complete pipeline from normalization through detection to risk escalation.
/// </summary>
public class SentryAnalyzerTests
{
    private readonly SentryAnalyzer _analyzer;
    private readonly LogNormalizer _logNormalizer;
    private readonly AnalysisProfileProvider _profileProvider;

    public SentryAnalyzerTests()
    {
        _logNormalizer = new LogNormalizer();
        _profileProvider = new AnalysisProfileProvider();

        // Baseline detectors
        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        // Linux-specific detectors
        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        // Advanced threat detectors
        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var riskEscalator = new RiskEscalator();
        _analyzer = new SentryAnalyzer(_logNormalizer, _profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator);
    }

    [Fact]
    public void Analyze_EmptyLog_ReturnsEmptyResult()
    {
        // Arrange
        var emptyLog = "";

        // Act
        var result = _analyzer.Analyze(emptyLog, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(0, result.ParsedLines);
        Assert.Equal(0, result.TotalLines);
        Assert.Empty(result.Entries);
        Assert.Empty(result.Findings);
        Assert.Equal(DateTime.MinValue, result.TimeRangeStart);
        Assert.Equal(DateTime.MinValue, result.TimeRangeEnd);
    }

    [Fact]
    public void Analyze_ValidIptablesLog_ParsesCorrectly()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54322 DPT=443";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(2, result.ParsedLines);
        Assert.Equal(2, result.TotalLines);
        Assert.Equal(2, result.Entries.Count);
        Assert.All(result.Entries, e => Assert.Equal(LogFormat.Iptables, e.LogFormat));
    }

    [Fact]
    public void Analyze_ValidNftablesLog_ParsesCorrectly()
    {
        // Arrange
        var log = @"2026-01-19T10:15:32.123456+00:00 nf_tables: INPUT IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(1, result.ParsedLines);
        Assert.Equal(1, result.TotalLines);
        Assert.Single(result.Entries);
        Assert.Equal(LogFormat.Nftables, result.Entries[0].LogFormat);
    }

    [Fact]
    public void Analyze_PortScanDetectsCorrectly()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(5))
            .Generate();

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        Assert.NotNull(result.Findings);
        // Should detect port scan at Medium intensity with 20 ports
        Assert.Contains(result.Findings, f => f.Category == "PortScan");
    }

    [Fact]
    public void Analyze_WithIntensityLow_AppliesCorrectProfile()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 5, duration: TimeSpan.FromMinutes(1))
            .Generate();

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Low, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.ParsedLines > 0);
        // Low intensity filters to High+ severity only
        Assert.True(result.Findings.All(f => f.Severity >= Severity.High));
    }

    [Fact]
    public void Analyze_WithIntensityHigh_AppliesCorrectProfile()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 5, duration: TimeSpan.FromMinutes(1))
            .Generate();

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.High, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.ParsedLines > 0);
        // High intensity shows all severities including Info
        Assert.True(result.Findings.All(f => Enum.IsDefined(typeof(Severity), f.Severity)));
    }

    [Fact]
    public void Analyze_BeaconingDetectsCorrectly()
    {
        // Arrange - Create manual beaconing pattern with explicit Flags field
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 10; i++)
        {
            events.Add(new UnifiedEvent
            {
                Timestamp = startTime.AddMinutes(i),
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                DestinationPort = 80,
                Protocol = "TCP",
                LogFormat = LogFormat.Iptables,
                LinuxSpecific = new Dictionary<string, string>
                {
                    { "Flags", "SYN" } // Explicit flags to avoid false positives
                }
            });
        }
        var log = string.Join("\n", events.Select(e => FormatIptablesLine(e)));

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert — Beaconing activity may be absorbed into C2Channel by the
        // deduplication step when both detectors fire on the same tuple.
        Assert.True(result.ParsedLines > 0);
        Assert.NotNull(result.Findings);
        Assert.Contains(result.Findings, f => f.Category == "Beaconing" || f.Category == "C2Channel");
    }

    private string FormatIptablesLine(UnifiedEvent evt)
    {
        var flags = evt.LinuxSpecific.GetValueOrDefault("Flags", "");
        var flagStr = string.IsNullOrEmpty(flags) ? "" : $" FLAGS={flags}";
        return $"kernel: {evt.Timestamp:MMM dd HH:mm:ss} server IN=eth0 SRC={evt.SourceIP} DST={evt.DestinationIP} PROTO=TCP SPT=54321 DPT={evt.DestinationPort}{flagStr}";
    }

    [Fact]
    public void Analyze_TimeRangeIsCalculatedCorrectly()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:00:00 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80
kernel: Jan 19 10:15:00 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54322 DPT=443";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.NotEqual(DateTime.MinValue, result.TimeRangeStart);
        Assert.NotEqual(DateTime.MinValue, result.TimeRangeEnd);
        Assert.True(result.TimeRangeEnd >= result.TimeRangeStart);
    }

    [Fact]
    public void Analyze_BaselineAndLinuxDetectors_BothRun()
    {
        // Arrange - Use a scenario that triggers both baseline (port scan) and
        // Linux-specific (interface hopping) detectors. Both produce Medium+
        // severity, so they survive the MinSeverityToShow filter.
        var builder = new LogScenarioBuilder();
        var portScanLog = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(1))
            .Generate();

        // Append interface-hopping lines (rapid switching between interfaces)
        // that use the same source IP and happen within the 5-minute window
        var hoppingInterfaces = new[] { "eth0", "wlan0", "eth1", "wlan0", "eth0" };
        var hoppingLog = string.Join("\n", hoppingInterfaces.Select((iface, i) =>
            $"kernel: Jan 19 10:15:{40 + i:D2} server IN={iface} OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 LEN=60"));

        var log = portScanLog + "\n" + hoppingLog;

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert - Verify the pipeline ran end-to-end
        Assert.True(result.ParsedLines > 0, "Should parse log lines");
        Assert.NotNull(result.Findings);
        Assert.True(result.Findings.Count > 0, "Should produce findings from the scenario");

        // Verify at least one baseline finding exists (PortScan)
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.PortScan);

        // Verify at least one Linux-specific finding exists (InterfaceHopping)
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.InterfaceHopping);

        // Verify findings have populated core fields
        Assert.All(result.Findings, f =>
        {
            Assert.False(string.IsNullOrEmpty(f.Category));
            Assert.True(Enum.IsDefined(typeof(Severity), f.Severity));
            Assert.False(string.IsNullOrEmpty(f.ShortDescription));
        });
    }

    [Fact]
    public void Analyze_CancellationToken_ThrowsOnCancel()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(10))
            .Generate();
        var largeLog = string.Join("\n", Enumerable.Repeat(log, 100)); // Make it large
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        Assert.Throws<OperationCanceledException>(() =>
        {
            _analyzer.Analyze(largeLog, IntensityLevel.Medium, cts.Token);
        });
    }

    [Fact]
    public void Analyze_CustomProfile_UsesOverrides()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 3, duration: TimeSpan.FromMinutes(1))
            .Generate();

        var customProfile = new AnalysisProfile
        {
            EnablePortScan = true,
            PortScanMinPorts = 2, // Lower threshold
            PortScanWindowMinutes = 10
        };

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, customProfile);

        // Assert
        Assert.True(result.ParsedLines > 0);
        // With custom profile (PortScanMinPorts = 2), should detect port scan with 3 ports
        Assert.Contains(result.Findings, f => f.Category == "PortScan");
    }

    [Fact]
    public void Analyze_ProducesValidAnalysisResult()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1, result.TotalLines);
        Assert.Equal(1, result.ParsedLines);
        Assert.Single(result.Entries);
        Assert.Equal("192.168.1.100", result.Entries[0].SourceIP);
        Assert.NotNull(result.Findings);
        Assert.NotNull(result.ParseErrors);
        Assert.NotNull(result.Warnings);
    }

    [Fact]
    public void Analyze_RiskEscalator_EscalatesFindings()
    {
        // Arrange - Create scenario with correlated findings that trigger escalation:
        // PortScan (baseline) + FlagAnomaly (Linux) from the same source host
        // The RiskEscalator should escalate these to Critical severity.
        var builder = new LogScenarioBuilder();
        var portScanLog = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(2))
            .Generate();

        // Append XMAS-scan lines (FIN PSH URG) from the same source IP to trigger FlagAnomaly
        // The builder uses SRC=192.168.1.100, so we use the same source
        // Use timestamps close to DateTime.Now so temporal proximity check passes
        var flagBaseTime = DateTime.Now;
        var flagAnomalyLines = string.Join("\n", Enumerable.Range(0, 5).Select(i =>
            $"kernel: {flagBaseTime.AddSeconds(i):MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80 FIN PSH URG"));

        var log = portScanLog + "\n" + flagAnomalyLines;

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert - Verify detection
        Assert.True(result.ParsedLines > 0);
        Assert.True(result.Findings.Count > 0, "Should detect the port scan and flag anomalies");

        // Verify both categories are present
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.PortScan);
        Assert.Contains(result.Findings, f => f.Category == FindingCategories.FlagAnomaly);

        // Verify escalation: correlated findings from the same host should be Critical
        var escalated = result.Findings.Where(f =>
            (f.Category == FindingCategories.PortScan || f.Category == FindingCategories.FlagAnomaly)
            && f.Severity == Severity.Critical).ToList();
        Assert.True(escalated.Count > 0,
            "Correlated PortScan + FlagAnomaly findings should be escalated to Critical");

        // Sanity: all findings have valid severities
        Assert.All(result.Findings, f => Assert.True(Enum.IsDefined(typeof(Severity), f.Severity)));
    }

    [Fact]
    public void Analyze_WarningsAreCaptured()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert - Warnings list exists and is a readable collection
        Assert.NotNull(result.Warnings);
        Assert.IsType<List<string>>(result.Warnings);
    }

    [Fact]
    public void Analyze_NoParsedEvents_PreservesParserWarnings()
    {
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=70000 DPT=80
Jan 19 10:15:33 server kernel: net_ratelimit: 45 callbacks suppressed";

        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        Assert.Equal(0, result.ParsedLines);
        Assert.Equal(1, result.ParseErrorCount);
        Assert.Single(result.Warnings);
        Assert.Contains("45 callbacks", result.Warnings[0]);
    }

    [Fact]
    public void Analyze_DetectorException_AddsWarningWithType()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";
        var analyzer = new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            new IDetector[] { new ThrowingDetector() },
            Array.Empty<IDetector>(),
            Array.Empty<IDetector>(),
            new RiskEscalator());

        // Act
        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Single(result.Warnings);
        Assert.Contains(nameof(ThrowingDetector), result.Warnings[0]);
        Assert.Contains(nameof(InvalidOperationException), result.Warnings[0]);
    }

    private sealed class ThrowingDetector : IDetector
    {
        public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("boom");
        }
    }

    [Fact]
    public void Analyze_LinuxDetectorException_AddsWarningWithType()
    {
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";
        var analyzer = new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            Array.Empty<IDetector>(),
            new IDetector[] { new ThrowingDetector() },
            Array.Empty<IDetector>(),
            new RiskEscalator());

        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        Assert.Single(result.Warnings);
        Assert.Contains("Linux detector", result.Warnings[0]);
        Assert.Contains(nameof(ThrowingDetector), result.Warnings[0]);
    }

    [Fact]
    public void Analyze_AdvancedDetectorException_AddsWarningWithType()
    {
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";
        var analyzer = new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            Array.Empty<IDetector>(),
            Array.Empty<IDetector>(),
            new IDetector[] { new ThrowingDetector() },
            new RiskEscalator());

        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        Assert.Single(result.Warnings);
        Assert.Contains("Advanced detector", result.Warnings[0]);
        Assert.Contains(nameof(ThrowingDetector), result.Warnings[0]);
    }

    [Fact]
    public void Analyze_ParseErrors_AreTracked()
    {
        // Arrange - Mix of valid and invalid lines
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80
This is not a valid log line
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.101 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=443
Another invalid line";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.Equal(4, result.TotalLines);
        Assert.Equal(2, result.ParsedLines);
        Assert.NotNull(result.ParseErrors);
        // Invalid lines that lack SRC/DST/PROTO are tracked as skipped, not parse errors.
        Assert.Equal(0, result.ParseErrorCount);
        Assert.Equal(2, result.SkippedLineCount);
        Assert.Contains(result.Warnings, w => w.Contains("2") && w.Contains("skipped"));
    }

    [Fact]
    public void Analyze_LinuxDetectors_ProcessLinuxSpecificFields()
    {
        // Arrange - Log with basic fields
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);
        Assert.NotNull(result.Entries);
        // Entry should be parsed successfully
        var entry = result.Entries[0];
        Assert.NotNull(entry);
        Assert.Equal(LogFormat.Iptables, entry.LogFormat);
        // Verify basic fields are set
        Assert.Equal("192.168.1.100", entry.SourceIP);
        Assert.Equal("10.0.0.5", entry.DestinationIP);
        Assert.Equal(80, entry.DestinationPort);
    }

    [Fact]
    [Trait("Category", "Performance")]
    public void Analyze_Performance_LargeLogCompletesInTime()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 100, duration: TimeSpan.FromMinutes(5))
            .Generate();
        var largeLog = string.Join("\n", Enumerable.Repeat(log, 10)); // 1000 lines

        // Act
        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(largeLog, IntensityLevel.Medium, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        // Assert
        Assert.True(result.ParsedLines > 0);
        // Should complete in under 10 seconds for 1000 lines
        Assert.True(duration.TotalSeconds < 10.0,
            $"Analysis took {duration.TotalSeconds:F2}s, should be under 10 seconds");
    }

    [Fact]
    public void Analyze_NullLog_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _analyzer.Analyze(null!, IntensityLevel.Medium, CancellationToken.None));
    }

    [Fact]
    public void Analyze_PeriodicBeaconing_DeduplicatesOverlapWithC2()
    {
        // Arrange — build a clear periodic beacon: 12 events, exactly 120s apart,
        // to the same dest:port. This pattern matches both BeaconingDetector
        // (low std-dev intervals) and C2ChannelDetector (consistent intervals
        // within tolerance) at Medium intensity.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var logLines = new List<string>();
        for (int i = 0; i < 12; i++)
        {
            var ts = startTime.AddMinutes(2 * i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=192.168.1.50 DST=8.8.8.8 PROTO=TCP SPT=40000 DPT=443");
        }

        var log = string.Join("\n", logLines);

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0, "Should parse all beacon events");

        var beaconingFindings = result.Findings.Where(f => f.Category == "Beaconing").ToList();
        var c2Findings = result.Findings.Where(f => f.Category == "C2Channel").ToList();

        // At minimum, one of the detectors should fire
        Assert.True(beaconingFindings.Count > 0 || c2Findings.Count > 0,
            "Periodic beacon should trigger at least one detector");

        // When both detectors fire on the same tuple, the deduplication step
        // should absorb the Beaconing finding into the C2Channel finding.
        // So for the same (SourceHost, Target) pair, we should NOT see both.
        var beaconingTuples = beaconingFindings.Select(f => (f.SourceHost, f.Target)).ToHashSet();
        var c2Tuples = c2Findings.Select(f => (f.SourceHost, f.Target)).ToHashSet();
        var overlap = beaconingTuples.Intersect(c2Tuples).ToList();

        Assert.Empty(overlap);

        // If C2 was detected, its details should mention the Beaconing overlap
        if (c2Findings.Count > 0 && beaconingFindings.Count == 0)
        {
            Assert.All(c2Findings, f => Assert.Contains("Overlap note", f.Details));
        }
    }

    [Fact]
    public void Analyze_MaxFindingsPerDetector_TruncatesByCategoryAndWarns()
    {
        // Arrange — build 8 separate scan bursts separated by quiet gaps.
        // Each burst is a short burst of distinct-port events, producing one PortScan finding.
        // With MaxFindingsPerDetector=5, the cap triggers and emits a warning.
        var startTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        var srcIp = "10.0.0.99";

        for (int burst = 0; burst < 8; burst++)
        {
            for (int port = 0; port < 20; port++)
            {
                events.Add(new UnifiedEvent
                {
                    Timestamp = startTime.AddMinutes(burst * 30).AddSeconds(port),
                    SourceIP = srcIp,
                    DestinationIP = "192.168.1.1",
                    DestinationPort = 1000 + (burst * 20) + port,
                    Protocol = "TCP",
                    LogFormat = LogFormat.Iptables
                });
            }
        }

        var logLines = events.Select(e =>
            $"kernel: {e.Timestamp:MMM dd HH:mm:ss} server IN=eth0 SRC={e.SourceIP} DST={e.DestinationIP} PROTO=TCP SPT=12345 DPT={e.DestinationPort}")
            .ToList();
        var log = string.Join("\n", logLines);

        var profile = _profileProvider.GetProfile(IntensityLevel.Medium) with
        {
            MaxFindingsPerDetector = 5,
            MinSeverityToShow = Severity.Info // show everything so cap is visible
        };

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, profile);

        // Assert — PortScan category should be capped at 5
        var portScanFindings = result.Findings.Where(f => f.Category == "PortScan").ToList();
        Assert.True(portScanFindings.Count <= 5,
            $"PortScan findings should be capped at 5, got {portScanFindings.Count}");

        // A warning should be emitted about the truncation
        Assert.Contains(result.Warnings, w => w.Contains("PortScan") && w.Contains("truncated"));
    }

    [Fact]
    public void Analyze_MaxFindingsPerDetectorZero_NoTruncation()
    {
        // Arrange
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 30, duration: TimeSpan.FromMinutes(3))
            .Generate();

        var profile = _profileProvider.GetProfile(IntensityLevel.Medium) with
        {
            MaxFindingsPerDetector = 0, // disabled
            MinSeverityToShow = Severity.Info
        };

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, profile);

        // Assert — no truncation warning about PortScan should appear
        Assert.DoesNotContain(result.Warnings, w => w.Contains("truncated"));
    }

    [Fact]
    public void Analyze_BeaconingAndLateralMovement_EscalatesToCritical()
    {
        // Arrange — same internal host beacons externally AND laterally moves internally.
        // Both findings should be escalated to Critical by the RiskEscalator.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var logLines = new List<string>();

        // Beaconing: regular 2-minute intervals to external IP:443
        for (int i = 0; i < 12; i++)
        {
            var ts = startTime.AddMinutes(2 * i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=10.0.0.5 DST=8.8.8.8 PROTO=TCP SPT=40000 DPT=443");
        }

        // Lateral movement: same source connecting to multiple internal hosts on port 22
        var internalTargets = new[] { "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13" };
        for (int i = 0; i < internalTargets.Length; i++)
        {
            var ts = startTime.AddMinutes(i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=10.0.0.5 DST={internalTargets[i]} PROTO=TCP SPT=40001 DPT=22");
        }

        var log = string.Join("\n", logLines);

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0);

        var beaconing = result.Findings.Where(f => f.Category == FindingCategories.Beaconing).ToList();
        var lateral = result.Findings.Where(f => f.Category == FindingCategories.LateralMovement).ToList();

        Assert.True(beaconing.Count > 0 || lateral.Count > 0,
            "Should detect at least one of Beaconing or LateralMovement");

        // If both are present, they should be escalated to Critical
        var beaconingOrLateral = result.Findings.Where(f =>
            (f.Category == FindingCategories.Beaconing || f.Category == FindingCategories.LateralMovement)
            && f.Severity == Severity.Critical).ToList();

        Assert.True(beaconingOrLateral.Count > 0,
            "Correlated Beaconing + LateralMovement findings should be escalated to Critical");
    }

    [Fact]
    public void Analyze_Deduplication_MultipleOverlappingTuples_KeepsCorrectCounts()
    {
        // Arrange — two different sources each produce Beaconing+C2 on distinct tuples.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var logLines = new List<string>();

        // Source A beacons to 8.8.8.8:443 (C2 also detected)
        for (int i = 0; i < 12; i++)
        {
            var ts = startTime.AddMinutes(2 * i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=192.168.1.10 DST=8.8.8.8 PROTO=TCP SPT=40000 DPT=443");
        }

        // Source B beacons to 1.1.1.1:443 (C2 also detected)
        for (int i = 0; i < 12; i++)
        {
            var ts = startTime.AddMinutes(2 * i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=192.168.1.20 DST=1.1.1.1 PROTO=TCP SPT=40000 DPT=443");
        }

        var log = string.Join("\n", logLines);

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        var beaconing = result.Findings.Where(f => f.Category == "Beaconing").ToList();
        var c2 = result.Findings.Where(f => f.Category == "C2Channel").ToList();

        // No overlapping tuples between Beaconing and C2
        var beaconingTuples = beaconing.Select(f => (f.SourceHost, f.Target)).ToHashSet();
        var c2Tuples = c2.Select(f => (f.SourceHost, f.Target)).ToHashSet();
        Assert.Empty(beaconingTuples.Intersect(c2Tuples));

        // Both C2 tuples should be present (one per source)
        Assert.Equal(2, c2.Count);
    }

    [Fact]
    public void Analyze_Deduplication_C2Only_PreservesC2()
    {
        // Arrange — mixed intervals: 7 deltas at 60s and 4 deltas at 300s.
        // C2 buckets find the 60s pattern (7 deltas >= 3, 8 pattern events >= 6).
        // Beaconing's TrimIntervals trims 2 outliers (trimPercent=0.1, 11 deltas),
        // but the remaining [60x5, 300x2] still has high std-dev (~108), so
        // Beaconing's std-dev threshold (5) rejects it.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var timestamps = new[] { 0, 60, 120, 180, 240, 300, 360, 420, 720, 1020, 1320, 1620 };
        var logLines = new List<string>();

        foreach (var sec in timestamps)
        {
            var ts = startTime.AddSeconds(sec);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=192.168.1.10 DST=8.8.8.8 PROTO=TCP SPT=40000 DPT=443");
        }

        var log = string.Join("\n", logLines);

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        var c2 = result.Findings.Where(f => f.Category == "C2Channel").ToList();
        Assert.NotEmpty(c2);

        // Beaconing should NOT fire because even after trimming the variance is too high
        Assert.DoesNotContain(result.Findings, f => f.Category == "Beaconing");

        // C2 should NOT have an overlap note because Beaconing was absent
        Assert.All(c2, f => Assert.DoesNotContain("Overlap note", f.Details));
    }

    [Fact]
    public void Analyze_Deduplication_BeaconingOnly_PreservesBeaconing()
    {
        // Arrange — Beaconing pattern with C2 disabled so only Beaconing fires.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var logLines = new List<string>();

        for (int i = 0; i < 12; i++)
        {
            var ts = startTime.AddMinutes(2 * i);
            logLines.Add($"kernel: {ts:MMM dd HH:mm:ss} server IN=eth0 SRC=192.168.1.10 DST=8.8.8.8 PROTO=TCP SPT=40000 DPT=443");
        }

        var log = string.Join("\n", logLines);

        var profile = _profileProvider.GetProfile(IntensityLevel.Medium) with
        {
            EnableC2Detection = false
        };

        // Act
        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, profile);

        // Assert
        var beaconing = result.Findings.Where(f => f.Category == "Beaconing").ToList();
        Assert.NotEmpty(beaconing);
        Assert.DoesNotContain(result.Findings, f => f.Category == "C2Channel");
    }

    [Fact]
    public void Analyze_SeverityFilterRunsBeforeFindingCap_PreservesVisibleFindings()
    {
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0);
        var detector = new StubDetector(
        [
            new Finding
            {
                Category = FindingCategories.UnusualPacketSize,
                Severity = Severity.Low,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5",
                TimeRangeStart = startTime,
                TimeRangeEnd = startTime,
                ShortDescription = "Low severity hidden finding",
                Details = "Should be removed by the severity filter."
            },
            new Finding
            {
                Category = FindingCategories.UnusualPacketSize,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5",
                TimeRangeStart = startTime,
                TimeRangeEnd = startTime,
                ShortDescription = "High severity visible finding",
                Details = "Should survive the per-category cap."
            }
        ]);

        var analyzer = new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            [detector],
            [],
            [],
            new RiskEscalator());

        var profile = _profileProvider.GetProfile(IntensityLevel.Medium) with
        {
            MaxFindingsPerDetector = 1,
            MinSeverityToShow = Severity.Medium
        };

        var log = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80";

        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, profile);

        var finding = Assert.Single(result.Findings);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("High severity visible finding", finding.ShortDescription);
    }

    [Fact]
    [Trait("Category", "Timing")]
    public void Analyze_CancellationToken_MidPipeline_RespectsCancellation()
    {
        // Arrange — large log that takes longer than 1ms to normalize + detect
        var builder = new LogScenarioBuilder();
        var log = builder
            .BuildPortScan(targetCount: 100, duration: TimeSpan.FromMinutes(5))
            .Generate();
        var largeLog = string.Join("\n", Enumerable.Repeat(log, 50)); // ~5K lines

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(1));

        // Act & Assert
        var ex = Assert.Throws<OperationCanceledException>(() =>
            _analyzer.Analyze(largeLog, IntensityLevel.Medium, cts.Token));

        Assert.Equal(cts.Token, ex.CancellationToken);
    }

    private sealed class StubDetector : IDetector
    {
        private readonly IReadOnlyList<Finding> _findings;

        public StubDetector(IReadOnlyList<Finding> findings)
        {
            _findings = findings;
        }

        public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            return new DetectionResult(_findings);
        }
    }

    [Fact]
    public void Analyze_MultipleC2FindingsSameTuple_DoesNotDropDistinctIntervals()
    {
        // Regression: C2ChannelDetector can emit multiple findings for the same
        // (SourceHost, Target) tuple when distinct periodic intervals are detected.
        // The dedup logic must not silently drop the second C2 finding when
        // Beaconing findings also exist for the same tuple.
        var startTime = new DateTime(2026, 6, 15, 10, 0, 0, DateTimeKind.Utc);
        var srcHost = "192.168.1.100";
        var target = "203.0.113.50:443";

        var detector = new StubDetector(
        [
            // Two C2 findings for the same tuple (different intervals)
            new Finding
            {
                Category = FindingCategories.C2Channel,
                Severity = Severity.High,
                SourceHost = srcHost,
                Target = target,
                TimeRangeStart = startTime,
                TimeRangeEnd = startTime.AddSeconds(150),
                ShortDescription = $"Potential C2 channel detected: {srcHost}-{target}",
                Details = "Detected 6 events with approximately 30s intervals."
            },
            new Finding
            {
                Category = FindingCategories.C2Channel,
                Severity = Severity.High,
                SourceHost = srcHost,
                Target = target,
                TimeRangeStart = startTime.AddSeconds(180),
                TimeRangeEnd = startTime.AddSeconds(480),
                ShortDescription = $"Potential C2 channel detected: {srcHost}-{target}",
                Details = "Detected 6 events with approximately 60s intervals."
            },
            // One Beaconing finding for the same tuple (triggers the dedup path)
            new Finding
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = srcHost,
                Target = target,
                TimeRangeStart = startTime,
                TimeRangeEnd = startTime.AddSeconds(480),
                ShortDescription = $"Beaconing detected from {srcHost}",
                Details = "Regular interval connections detected."
            }
        ]);

        var analyzer = new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            [detector],
            [],
            [],
            new RiskEscalator()
        );

        // Minimal raw log to pass normalization
        var log = $"kernel: {startTime:MMM dd HH:mm:ss} server IN=eth0 SRC={srcHost} DST=203.0.113.50 PROTO=TCP SPT=12345 DPT=443";

        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

        var c2Findings = result.Findings.Where(f => f.Category == "C2Channel").ToList();
        Assert.Equal(2, c2Findings.Count);
        Assert.Contains(c2Findings, f => f.Details.Contains("30"));
        Assert.Contains(c2Findings, f => f.Details.Contains("60"));
    }

    [Fact]
    public void Analyze_WithReferenceDate_UsesProvidedYear()
    {
        // Iptables logs don't include the year. Without referenceDate, the parser
        // uses DateTime.Now. With referenceDate, it should use the provided date.
        var referenceDate = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var log = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, referenceDate: referenceDate);

        Assert.Single(result.Entries);
        Assert.Equal(2025, result.Entries[0].Timestamp.Year);
    }
}
