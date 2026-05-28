using System.Diagnostics;
using System.Text;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Performance;

/// <summary>
/// Utility for benchmarking performance of the analysis engine.
/// </summary>
public class PerformanceBenchmark
{
    private readonly SentryAnalyzer _analyzer;

    public PerformanceBenchmark()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

        // All detector types for comprehensive testing
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
        _analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator);
    }

    /// <summary>
    /// Runs performance benchmark for different log sizes.
    /// </summary>
    public BenchmarkResult RunBenchmark(int[] logSizes, IntensityLevel intensity = IntensityLevel.Medium)
    {
        var results = new List<BenchmarkRunResult>();
        
        foreach (var size in logSizes)
        {
            var result = RunSingleBenchmark(size, intensity);
            results.Add(result);
        }

        return new BenchmarkResult
        {
            Runs = results.ToArray(),
            AverageProcessingRate = results.Average(r => r.ProcessingRate),
            OverallAverageTime = results.Average(r => r.ElapsedMs)
        };
    }

    /// <summary>
    /// Runs a single benchmark with specified log size.
    /// </summary>
    private BenchmarkRunResult RunSingleBenchmark(int logSize, IntensityLevel intensity)
    {
        var log = GenerateTestLog(logSize);
        var stopwatch = Stopwatch.StartNew();
        
        var analysisResult = _analyzer.Analyze(log, intensity, CancellationToken.None);
        
        stopwatch.Stop();

        var processingRate = logSize > 0 ? (double)analysisResult.ParsedLines / (stopwatch.ElapsedMilliseconds / 1000.0) : 0;

        return new BenchmarkRunResult
        {
            LogSize = logSize,
            ParsedLines = analysisResult.ParsedLines,
            ElapsedMs = stopwatch.ElapsedMilliseconds,
            ProcessingRate = processingRate,
            FindingsCount = analysisResult.Findings.Count,
            MemoryBeforeKB = GC.GetTotalMemory(false) / 1024,
            MemoryAfterKB = GC.GetTotalMemory(true) / 1024
        };
    }

    /// <summary>
    /// Generates a test log with specified number of lines.
    /// </summary>
    private string GenerateTestLog(int lineCount)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;
        
        for (int i = 0; i < lineCount; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            var sourceIp = $"192.168.1.{(i % 254) + 2}";
            var destIp = $"10.0.0.{(i % 254) + 2}";
            var port = 80 + (i % 1000);
            
            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT={50000 + (i % 10000)} DPT={port} LEN=60");
        }

        return sb.ToString();
    }
}

/// <summary>
/// Result of a performance benchmark run.
/// </summary>
public class BenchmarkResult
{
    public BenchmarkRunResult[] Runs { get; set; } = Array.Empty<BenchmarkRunResult>();
    public double AverageProcessingRate { get; set; }
    public double OverallAverageTime { get; set; }
}

/// <summary>
/// Result of a single benchmark run.
/// </summary>
public class BenchmarkRunResult
{
    public int LogSize { get; set; }
    public int ParsedLines { get; set; }
    public long ElapsedMs { get; set; }
    public double ProcessingRate { get; set; } // Lines per second
    public int FindingsCount { get; set; }
    public long MemoryBeforeKB { get; set; }
    public long MemoryAfterKB { get; set; }
    public long MemoryDeltaKB => MemoryAfterKB - MemoryBeforeKB;
}
