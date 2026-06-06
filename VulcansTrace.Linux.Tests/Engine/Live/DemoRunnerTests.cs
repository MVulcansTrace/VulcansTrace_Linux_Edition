using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class DemoRunnerTests : IDisposable
{
    private readonly LiveStreamAnalyzer _analyzer;

    public DemoRunnerTests()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();
        var baseline = new IDetector[] { new PortScanDetector(), new FloodDetector() };
        var linux = new IDetector[] { new FlagAnomalyDetector(), new MacSpoofingDetector() };
        var advanced = new IDetector[] { new C2ChannelDetector(), new PrivilegeEscalationDetector() };
        var riskEscalator = new RiskEscalator();
        var sentry = new SentryAnalyzer(logNormalizer, profileProvider, baseline, linux, advanced, riskEscalator);

        _analyzer = new LiveStreamAnalyzer(
            sentry,
            profileProvider,
            timeWindow: TimeSpan.FromSeconds(120),
            analysisInterval: TimeSpan.FromMilliseconds(200),
            analysisEventThreshold: 50,
            fingerprintTtl: TimeSpan.FromSeconds(5));
    }

    public void Dispose()
    {
        _analyzer.Dispose();
    }

    [Theory]
    [InlineData(DemoScenario.SshBruteforce)]
    [InlineData(DemoScenario.PrivilegeEscalation)]
    public async Task RunAsync_ShortRun_ProducesFindings(DemoScenario scenario)
    {
        var runner = new DemoRunner(_analyzer);
        var result = await runner.RunAsync(scenario, TimeSpan.FromSeconds(5), IntensityLevel.High, seed: 42);

        Assert.NotNull(result);
        Assert.NotNull(result.AnalysisResult);
        Assert.NotNull(result.TraceMap);
        Assert.Equal(scenario, result.Scenario);
        Assert.True(result.Duration.TotalSeconds >= 4); // Allow slight timing variance
        Assert.NotEmpty(result.RawLogDescription);
    }

    [Fact]
    public async Task RunAsync_C2Beaconing_CompletesWithoutError()
    {
        var runner = new DemoRunner(_analyzer);
        var result = await runner.RunAsync(DemoScenario.C2Beaconing, TimeSpan.FromSeconds(10), IntensityLevel.High, seed: 42);

        Assert.NotNull(result);
        Assert.NotNull(result.AnalysisResult);
        Assert.NotNull(result.TraceMap);
    }

    [Fact]
    public async Task RunAsync_SshBruteforce_ProducesFloodFindings()
    {
        var runner = new DemoRunner(_analyzer);
        var result = await runner.RunAsync(DemoScenario.SshBruteforce, TimeSpan.FromSeconds(5), IntensityLevel.High, seed: 42);

        var findings = result.AnalysisResult.Findings;
        Assert.Contains(findings, finding => finding.Category == FindingCategories.Flood);
        Assert.Contains(findings, finding => finding.Category == FindingCategories.PrivilegeEscalation);
        Assert.DoesNotContain(findings, finding => finding.Category == FindingCategories.PortScan);
    }

    [Fact]
    public async Task RunAsync_PrivilegeEscalation_ProducesOnlyPrivilegeFindings()
    {
        var runner = new DemoRunner(_analyzer);
        var result = await runner.RunAsync(DemoScenario.PrivilegeEscalation, TimeSpan.FromSeconds(3), IntensityLevel.High, seed: 42);

        var findings = result.AnalysisResult.Findings;
        Assert.NotEmpty(findings);
        Assert.All(findings, finding => Assert.Equal(FindingCategories.PrivilegeEscalation, finding.Category));
    }

    [Fact]
    public async Task RunAsync_Cancellation_StopsGracefully()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var runner = new DemoRunner(_analyzer);

        var result = await runner.RunAsync(DemoScenario.SshBruteforce, TimeSpan.FromSeconds(10), IntensityLevel.High, seed: 42, cts.Token);

        Assert.NotNull(result);
        // Cancellation at 2s, but StopAsync and task cleanup can add overhead.
        Assert.True(result.Duration.TotalSeconds < 8, $"Should have stopped early due to cancellation, but ran for {result.Duration.TotalSeconds}s.");
    }

    [Fact]
    public async Task RunAsync_SetsTimeRange()
    {
        var runner = new DemoRunner(_analyzer);
        var result = await runner.RunAsync(DemoScenario.PrivilegeEscalation, TimeSpan.FromSeconds(3), IntensityLevel.High, seed: 42);

        Assert.True(result.StartTime > DateTime.MinValue);
        Assert.True(result.EndTime > result.StartTime);
        Assert.Equal(result.StartTime, result.AnalysisResult.TimeRangeStart);
        Assert.Equal(result.EndTime, result.AnalysisResult.TimeRangeEnd);
    }
}
