using Xunit;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Integration;

public sealed class ProfileComparisonTests : IDisposable
{
    private readonly SentryAnalyzer _analyzer;
    private readonly string _iptablesAttackLogPath;

    public ProfileComparisonTests()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

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

        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var samplesDir = Path.Combine(baseDir, "Data", "Real", "Samples");
        _iptablesAttackLogPath = Path.Combine(samplesDir, "large-portscan.log");
    }

    [Fact]
    public void ProfileComparison_AllProfiles_ParseSameEntryCount()
    {
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        var lowResult = _analyzer.Analyze(logContent, IntensityLevel.Low, CancellationToken.None);
        var mediumResult = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);
        var highResult = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        Assert.True(lowResult.Entries.Count > 0, "Low intensity should parse events");
        Assert.Equal(lowResult.Entries.Count, mediumResult.Entries.Count);
        Assert.Equal(lowResult.Entries.Count, highResult.Entries.Count);
    }

    [Fact]
    public void ProfileComparison_FindingsMonotonicallyIncrease()
    {
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        var lowResult = _analyzer.Analyze(logContent, IntensityLevel.Low, CancellationToken.None);
        var mediumResult = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);
        var highResult = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        Assert.True(lowResult.Findings.Count <= mediumResult.Findings.Count,
            $"Low findings ({lowResult.Findings.Count}) should be <= Medium ({mediumResult.Findings.Count})");
        Assert.True(mediumResult.Findings.Count <= highResult.Findings.Count,
            $"Medium findings ({mediumResult.Findings.Count}) should be <= High ({highResult.Findings.Count})");
    }

    [Fact]
    public void ProfileComparison_HighProfileIncludesMoreCategoriesThanLow()
    {
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        var lowResult = _analyzer.Analyze(logContent, IntensityLevel.Low, CancellationToken.None);
        var highResult = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        var lowCategories = lowResult.Findings.Select(f => f.Category).ToHashSet();
        var highCategories = highResult.Findings.Select(f => f.Category).ToHashSet();

        Assert.True(highCategories.Count >= lowCategories.Count,
            $"High profile categories ({highCategories.Count}) should be >= Low ({lowCategories.Count})");
    }

    [Fact]
    public void ProfileComparison_ExpectedCategoriesPresentAtHighIntensity()
    {
        var logContent = File.ReadAllText(_iptablesAttackLogPath);
        var highResult = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        var categories = highResult.Findings.Select(f => f.Category).ToHashSet();
        Assert.Contains(FindingCategories.PortScan, categories);
    }

    [Fact]
    public void ProfileComparison_NoUnexpectedParseErrors()
    {
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        var lowResult = _analyzer.Analyze(logContent, IntensityLevel.Low, CancellationToken.None);
        var mediumResult = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);
        var highResult = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        Assert.Equal(0, lowResult.ParseErrorCount);
        Assert.Equal(0, mediumResult.ParseErrorCount);
        Assert.Equal(0, highResult.ParseErrorCount);
    }

    public void Dispose()
    {
    }
}
