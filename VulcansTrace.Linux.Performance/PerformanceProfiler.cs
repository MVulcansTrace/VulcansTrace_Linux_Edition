using System.Diagnostics;
using System.Text;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Performance;

/// <summary>
/// Tool for profiling the performance of different components of the analysis engine.
/// </summary>
public class PerformanceProfiler
{
    private readonly SentryAnalyzer _analyzer;

    public PerformanceProfiler()
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
    /// Profiles the performance of the entire analysis pipeline.
    /// </summary>
    public async Task<ProfileResult> ProfileAnalysisAsync(string log, IntensityLevel intensity = IntensityLevel.Medium)
    {
        return await Task.Run(() =>
        {
            var result = new ProfileResult();

            // Profile normalization
            var logNormalizer = new LogNormalizer();
            var sw = Stopwatch.StartNew();
            var normResult = logNormalizer.Normalize(log);
            sw.Stop();
            result.NormalizationTimeMs = sw.ElapsedMilliseconds;
            result.NormalizedEvents = normResult.Events.Length;

            // Profile analysis
            sw.Restart();
            var analysisResult = _analyzer.Analyze(log, intensity, CancellationToken.None);
            sw.Stop();
            result.AnalysisTimeMs = sw.ElapsedMilliseconds;
            result.FindingsCount = analysisResult.Findings.Count;

            // Profile individual detector performance
            result.DetectorProfiles = ProfileDetectors(log, intensity);

            return result;
        });
    }

    /// <summary>
    /// Profiles individual detectors separately.
    /// </summary>
    private DetectorProfile[] ProfileDetectors(string log, IntensityLevel intensity)
    {
        var profileProvider = new AnalysisProfileProvider();
        var profile = profileProvider.GetProfile(intensity);

        var logNormalizer = new LogNormalizer();
        var normalized = logNormalizer.Normalize(log);

        var results = new List<DetectorProfile>();

        // Profile baseline detectors
        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        foreach (var detector in baselineDetectors)
        {
            var sw = Stopwatch.StartNew();
            var findings = detector.Detect(normalized.Events, profile, CancellationToken.None);
            sw.Stop();

            results.Add(new DetectorProfile
            {
                Name = detector.GetType().Name,
                Category = "Baseline",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
                FindingsCount = findings.Findings.Count
            });
        }

        // Profile Linux-specific detectors
        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        foreach (var detector in linuxDetectors)
        {
            var sw = Stopwatch.StartNew();
            var findings = detector.Detect(normalized.Events, profile, CancellationToken.None);
            sw.Stop();

            results.Add(new DetectorProfile
            {
                Name = detector.GetType().Name,
                Category = "Linux-Specific",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
                FindingsCount = findings.Findings.Count
            });
        }

        // Profile advanced detectors
        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        foreach (var detector in advancedDetectors)
        {
            var sw = Stopwatch.StartNew();
            var findings = detector.Detect(normalized.Events, profile, CancellationToken.None);
            sw.Stop();

            results.Add(new DetectorProfile
            {
                Name = detector.GetType().Name,
                Category = "Advanced",
                ExecutionTimeMs = sw.ElapsedMilliseconds,
                FindingsCount = findings.Findings.Count
            });
        }

        return results.ToArray();
    }
}

/// <summary>
/// Result of a performance profiling run.
/// </summary>
public class ProfileResult
{
    public long NormalizationTimeMs { get; set; }
    public long AnalysisTimeMs { get; set; }
    public int NormalizedEvents { get; set; }
    public int FindingsCount { get; set; }
    public DetectorProfile[] DetectorProfiles { get; set; } = Array.Empty<DetectorProfile>();
}

/// <summary>
/// Performance profile for a single detector.
/// </summary>
public class DetectorProfile
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public long ExecutionTimeMs { get; set; }
    public int FindingsCount { get; set; }
}