using System.Diagnostics;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;

namespace VulcansTrace.Linux.Tests.Integration;

[Trait("Category", "Performance")]
public class PerformanceTests : IDisposable
{
    private readonly SentryAnalyzer _analyzer;
    private readonly LogNormalizer _logNormalizer;
    private readonly AnalysisProfileProvider _profileProvider;

    public PerformanceTests()
    {
        _logNormalizer = new LogNormalizer();
        _profileProvider = new AnalysisProfileProvider();

        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var riskEscalator = new RiskEscalator();
        _analyzer = new SentryAnalyzer(_logNormalizer, _profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator);
    }

    [Fact]
    public void Analyze_1000Lines_CompletesWithin5Seconds()
    {
        var builder = new LogScenarioBuilder();
        var baseLog = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(5))
            .Generate();
        var log1000Lines = string.Join("\n", Enumerable.Repeat(baseLog, 50));

        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(log1000Lines, IntensityLevel.Medium, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        Assert.True(result.ParsedLines > 0, "Should parse some lines");
        Assert.True(duration.TotalSeconds < 5.0,
            $"Analysis of 1000 lines took {duration.TotalSeconds:F2}s, should be under 5 seconds. Parsed: {result.ParsedLines} lines");
    }

    [Fact]
    public void Analyze_5000Lines_CompletesWithin15Seconds()
    {
        var builder = new LogScenarioBuilder();
        var baseLog = builder
            .BuildPortScan(targetCount: 30, duration: TimeSpan.FromMinutes(10))
            .Generate();
        var log5000Lines = string.Join("\n", Enumerable.Repeat(baseLog, 100));

        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(log5000Lines, IntensityLevel.Medium, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        Assert.True(result.ParsedLines > 0, "Should parse some lines");
        Assert.True(duration.TotalSeconds < 15.0,
            $"Analysis of 5000 lines took {duration.TotalSeconds:F2}s, should be under 15 seconds. Parsed: {result.ParsedLines} lines");
    }

    [Fact]
    public void Analyze_Throughput_ParsesAtLeast100LinesPerSecond()
    {
        var builder = new LogScenarioBuilder();
        var baseLog = builder
            .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(5))
            .Generate();
        var log2000Lines = string.Join("\n", Enumerable.Repeat(baseLog, 100));

        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(log2000Lines, IntensityLevel.Medium, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        Assert.True(result.ParsedLines > 0, "Should parse some lines");
        var linesPerSecond = result.ParsedLines / duration.TotalSeconds;
        Assert.True(linesPerSecond >= 100,
            $"Throughput is {linesPerSecond:F2} lines/sec, should be at least 100 lines/sec. Duration: {duration.TotalSeconds:F2}s");
    }

    [Fact]
    public void Analyze_MemoryUsage_DoesNotExceedLimitsForLargeLogs()
    {
        var builder = new LogScenarioBuilder();
        var baseLog = builder
            .BuildPortScan(targetCount: 50, duration: TimeSpan.FromMinutes(10))
            .Generate();
        var log10000Lines = string.Join("\n", Enumerable.Repeat(baseLog, 200));

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var memoryBefore = GC.GetTotalMemory(true);

        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(log10000Lines, IntensityLevel.High, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var memoryAfter = GC.GetTotalMemory(false);
        var memoryUsed = memoryAfter - memoryBefore;

        Assert.True(result.ParsedLines > 0, "Should parse some lines");
        Assert.True(duration.TotalSeconds < 30.0,
            $"Analysis took {duration.TotalSeconds:F2}s, should be under 30 seconds for 10000 lines");

        var memoryUsedMB = Math.Abs(memoryUsed) / (1024.0 * 1024.0);
        Assert.True(memoryUsedMB < 750,
            $"Memory usage is {memoryUsedMB:F2} MB, should be under 750 MB. Parsed: {result.ParsedLines} lines");
    }

    [Fact]
    public void Analyze_AllIntensityLevels_CompleteWithinBudget()
    {
        const int sampleCount = 5;
        var maxAllowedDuration = TimeSpan.FromSeconds(5);
        var varianceFloor = TimeSpan.FromMilliseconds(250);
        var builder = new LogScenarioBuilder();
        var baseLog = builder
            .BuildPortScan(targetCount: 25, duration: TimeSpan.FromMinutes(5))
            .Generate();
        var log1000Lines = string.Join("\n", Enumerable.Repeat(baseLog, 50));

        MeasureAnalysisTime(log1000Lines, IntensityLevel.Low);
        MeasureAnalysisTime(log1000Lines, IntensityLevel.Medium);
        MeasureAnalysisTime(log1000Lines, IntensityLevel.High);

        var lowSamples = new List<TimeSpan>(sampleCount);
        var mediumSamples = new List<TimeSpan>(sampleCount);
        var highSamples = new List<TimeSpan>(sampleCount);

        for (var i = 0; i < sampleCount; i++)
        {
            lowSamples.Add(MeasureAnalysisTime(log1000Lines, IntensityLevel.Low));
            mediumSamples.Add(MeasureAnalysisTime(log1000Lines, IntensityLevel.Medium));
            highSamples.Add(MeasureAnalysisTime(log1000Lines, IntensityLevel.High));
        }

        var lowDuration = Median(lowSamples);
        var mediumDuration = Median(mediumSamples);
        var highDuration = Median(highSamples);

        Assert.True(lowDuration < maxAllowedDuration, $"Low intensity took {lowDuration.TotalSeconds:F2}s");
        Assert.True(mediumDuration < maxAllowedDuration, $"Medium intensity took {mediumDuration.TotalSeconds:F2}s");
        Assert.True(highDuration < maxAllowedDuration, $"High intensity took {highDuration.TotalSeconds:F2}s");

        var maxDuration = Math.Max(lowDuration.TotalSeconds, Math.Max(mediumDuration.TotalSeconds, highDuration.TotalSeconds));
        var minDuration = Math.Min(lowDuration.TotalSeconds, Math.Min(mediumDuration.TotalSeconds, highDuration.TotalSeconds));

        if (TimeSpan.FromSeconds(maxDuration) < varianceFloor)
            return;

        var variance = (maxDuration - minDuration) / Math.Max(minDuration, 0.001);

        Assert.True(variance < 2.0,
            $"Performance variance is {variance:P2}, should be under 200%. Times: Low={lowDuration.TotalSeconds:F2}s, Medium={mediumDuration.TotalSeconds:F2}s, High={highDuration.TotalSeconds:F2}s");
    }

    private TimeSpan MeasureAnalysisTime(string log, IntensityLevel intensity)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = _analyzer.Analyze(log, intensity, CancellationToken.None);
        stopwatch.Stop();

        Assert.True(result.ParsedLines > 0);

        return stopwatch.Elapsed;
    }

    private static TimeSpan Median(IReadOnlyList<TimeSpan> durations)
    {
        var ordered = durations.OrderBy(d => d).ToArray();
        return ordered[ordered.Length / 2];
    }

    [Fact]
    public void UnusualPacketSizeDetector_10KEventsAcross100Tuples_CompletesWithin2Seconds()
    {
        // Arrange — generate 10,000 events across 150 distinct (src, dst, port, proto) tuples.
        // Each event has a parseable LEN= field so the detector processes them.
        // This specifically exercises the consistency/variance analysis loop that
        // was previously O(N×M) due to events.Where() re-scanning.
        var startTime = DateTime.Now;
        var events = new List<UnifiedEvent>();
        var random = new Random(42);

        for (int tuple = 0; tuple < 150; tuple++)
        {
            var srcIp = $"10.1.{tuple / 256}.{tuple % 256}";
            var dstIp = $"10.2.{tuple / 256}.{tuple % 256}";
            var dstPort = 1024 + tuple;

            // ~67 events per tuple → 10,050 total
            for (int i = 0; i < 67; i++)
            {
                events.Add(new UnifiedEvent
                {
                    Timestamp = startTime.AddSeconds(i + tuple * 100),
                    SourceIP = srcIp,
                    DestinationIP = dstIp,
                    DestinationPort = dstPort,
                    Protocol = "TCP",
                    LogFormat = LogFormat.Iptables,
                    LinuxSpecific = new Dictionary<string, string>
                    {
                        { "Length", (random.Next(40, 1500)).ToString() }
                    }
                });
            }
        }

        var detector = new UnusualPacketSizeDetector();
        var profile = new AnalysisProfile
        {
            EnableUnusualPacketSize = true,
            PacketSizeMinForAnalysis = 5,
            PacketSizeConsistencyPercent = 60,
            PacketSizeMinConsistentCount = 5,
            PacketSizeLargeThreshold = 3000,
            PacketSizeSmallThreshold = 40,
            PacketSizeVarianceRatio = 0.5,
            PacketSizeMinAvgForVariance = 100
        };

        // Act
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
        sw.Stop();

        // Assert
        Assert.True(sw.Elapsed.TotalSeconds < 2.0,
            $"UnusualPacketSizeDetector took {sw.Elapsed.TotalSeconds:F2}s for {events.Count} events across 150 tuples, should be under 2s. Findings: {findings.Count}");
        // Sanity: detector should not crash and should produce some output
        Assert.True(events.Count >= 10000, $"Expected >= 10000 events, got {events.Count}");
    }

    [Fact]
    public void LogNormalizer_100KLines_SingleSplitCompletesWithin5Seconds()
    {
        // Arrange — generate a 100K-line iptables log to exercise the
        // single-split path through LogNormalizer.Normalize.
        // Previously the log text was split 3 times (DetectFormat, totalLines, parser).
        // The refactored code splits once and reuses the array.
        var logLines = Enumerable.Range(0, 100_000)
            .Select(i => $"kernel: Jan 19 10:{(i / 60) % 60:D2}:{i % 60:D2} server IN=eth0 SRC=192.168.1.{(i % 254) + 1} DST=10.0.0.{(i % 10) + 1} PROTO=TCP SPT={1024 + (i % 60000)} DPT={new[] { 22, 80, 443, 3389, 8080 }[i % 5]} LEN={40 + (i % 1400)}");
        var log100K = string.Join("\n", logLines);

        // Act
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = _logNormalizer.Normalize(log100K);
        sw.Stop();

        // Assert
        Assert.True(result.Events.Length > 0, $"Expected some parsed events, got {result.Events.Length}");
        Assert.True(sw.Elapsed.TotalSeconds < 5.0,
            $"LogNormalizer.Normalize took {sw.Elapsed.TotalSeconds:F2}s for {result.TotalLines} lines, should be under 5s. Parsed: {result.Events.Length}");
    }

    public void Dispose()
    {
    }
}
