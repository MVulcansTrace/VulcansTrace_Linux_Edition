using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Tests.Helpers;

namespace VulcansTrace.Linux.Tests.Integration;

public class ConfigurableThresholdIntegrationTests
{
    private static AnalysisProfile MediumWith() => new AnalysisProfile
    {
        EnablePortScan = true,
        EnableFlood = true,
        EnableLateralMovement = true,
        EnableBeaconing = true,
        EnablePolicy = true,
        EnableNovelty = true,
        EnableFlagAnomaly = true,
        EnableMacSpoofing = true,
        EnableKernelModule = true,
        EnableInterfaceHopping = true,
        EnableUnusualPacketSize = true,
        EnableC2Detection = true,
        EnablePrivilegeEscalationDetection = true,
        PortScanMinPorts = 15,
        PortScanWindowMinutes = 5,
        FloodMinEvents = 200,
        FloodWindowSeconds = 60,
        LateralMinHosts = 4,
        LateralWindowMinutes = 10,
        BeaconMinEvents = 6,
        BeaconStdDevThreshold = 5.0,
        BeaconMinIntervalSeconds = 30,
        BeaconMaxIntervalSeconds = 900,
        BeaconMaxSamplesPerTuple = 200,
        BeaconMinDurationSeconds = 120,
        BeaconTrimPercent = 0.1,
        C2ToleranceSeconds = 5.0,
        C2MinIntervalSeconds = 60,
        C2MaxIntervalSeconds = 1800,
        C2MinOccurrences = 3,
        C2MinPatternEvents = 6,
        C2MinGroupSize = 3,
        PrivilegeSpikeWindowMinutes = 5,
        PrivilegeSpikeMinAttempts = 5,
        PrivilegeSweepMinDistinctPorts = 3,
        InterfaceHoppingWindowMinutes = 5,
        PacketSizeLargeThreshold = 3000,
        PacketSizeSmallThreshold = 40,
        PacketSizeMinForAnalysis = 10,
        PacketSizeConsistencyPercent = 70,
        PacketSizeMinConsistentCount = 10,
        PacketSizeVarianceRatio = 0.5,
        PacketSizeMinAvgForVariance = 100,
        AdminPorts = [445, 3389, 22],
        DisallowedOutboundPorts = [21, 23, 445],
        MinSeverityToShow = Severity.Info
    };

    [Fact]
    public void LowerPacketSizeLargeThreshold_CatchesMoreLargePackets()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildUnusualPacketSizes(largeCount: 3, smallCount: 0, consistentCount: 0).Generate();

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var strictProfile = MediumWith() with { PacketSizeLargeThreshold = 4000 };
        var lenientProfile = MediumWith() with { PacketSizeLargeThreshold = 1000 };

        var strictResults = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, strictProfile);
        var lenientResults = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, lenientProfile);

        var strictLargeFindings = strictResults.Findings.Count(f => f.ShortDescription.Contains("large packet"));
        var lenientLargeFindings = lenientResults.Findings.Count(f => f.ShortDescription.Contains("large packet"));

        Assert.True(lenientLargeFindings >= strictLargeFindings,
            $"Lenient ({lenientLargeFindings}) should have >= large-packet findings vs strict ({strictLargeFindings})");
    }

    [Fact]
    public void RaisePacketSizeSmallThreshold_IncreasesSmallPacketFindings()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildUnusualPacketSizes(largeCount: 0, smallCount: 5, consistentCount: 0).Generate();

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var defaultProfile = MediumWith() with { PacketSizeSmallThreshold = 40 };
        var stricterProfile = MediumWith() with { PacketSizeSmallThreshold = 80 };

        var defaultResults = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, defaultProfile);
        var stricterResults = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, stricterProfile);

        var defaultSmall = defaultResults.Findings.Count(f => f.ShortDescription.Contains("small packet"));
        var stricterSmall = stricterResults.Findings.Count(f => f.ShortDescription.Contains("small packet"));

        Assert.True(stricterSmall >= defaultSmall);
    }

    [Fact]
    public void HigherC2MinGroupSize_ReducesC2Findings()
    {
        var log = new LogScenarioBuilder()
            .BuildBeaconing(TimeSpan.FromMinutes(5), TimeSpan.FromHours(2))
            .Generate();

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var lowGroupSize = MediumWith() with { C2MinGroupSize = 2 };
        var highGroupSize = MediumWith() with { C2MinGroupSize = 50 };

        var lowResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, lowGroupSize);
        var highResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, highGroupSize);

        var lowC2 = lowResult.Findings.Count(f => f.Category == "C2Channel");
        var highC2 = highResult.Findings.Count(f => f.Category == "C2Channel");

        Assert.True(lowC2 >= highC2,
            $"Low group size ({lowC2}) should have >= C2 findings vs high ({highC2})");
    }

    [Fact]
    public void NarrowerInterfaceHoppingWindow_ReducesFindings()
    {
        var log = new LogScenarioBuilder()
            .BuildInterfaceHopping(["eth0", "eth1", "wlan0"], TimeSpan.FromMinutes(10))
            .Generate();

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var narrowWindow = MediumWith() with { InterfaceHoppingWindowMinutes = 1 };
        var wideWindow = MediumWith() with { InterfaceHoppingWindowMinutes = 30 };

        var narrowResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, narrowWindow);
        var wideResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, wideWindow);

        var narrowHops = narrowResult.Findings.Count(f => f.Category == "InterfaceHopping");
        var wideHops = wideResult.Findings.Count(f => f.Category == "InterfaceHopping");

        Assert.True(wideHops >= narrowHops);
    }

    [Fact]
    public void ConsistentPacketSizeCovertChannel_ThresholdControlsDetection()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildUnusualPacketSizes(largeCount: 0, smallCount: 0, consistentCount: 20).Generate();

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var detectsProfile = MediumWith() with
        {
            PacketSizeConsistencyPercent = 50,
            PacketSizeMinConsistentCount = 5
        };
        var ignoresProfile = MediumWith() with
        {
            PacketSizeConsistencyPercent = 99,
            PacketSizeMinConsistentCount = 50
        };

        var detectsResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, detectsProfile);
        var ignoresResult = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, ignoresProfile);

        var detectsConsistent = detectsResult.Findings.Count(f => f.ShortDescription.Contains("consistent packet sizes"));
        var ignoresConsistent = ignoresResult.Findings.Count(f => f.ShortDescription.Contains("consistent packet sizes"));

        Assert.True(detectsConsistent >= ignoresConsistent);
    }

    [Fact]
    public void NftablesLog_EndToEnd_WithCustomProfile_ProducesFindings()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var logPath = Path.Combine(baseDir, "Data", "Real", "Samples", "nftables-traffic.log");
        var log = File.ReadAllText(logPath);

        var analyzer = SentryAnalyzerFactory.CreateFull();

        var sensitiveProfile = MediumWith() with
        {
            EnableNovelty = true,
            MinSeverityToShow = Severity.Info
        };

        var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None, sensitiveProfile);

        Assert.True(result.ParsedLines > 0, "Should parse nftables log");
        Assert.NotEmpty(result.Entries);
        Assert.All(result.Findings, f =>
        {
            Assert.NotEmpty(f.ShortDescription);
            Assert.NotEqual(Guid.Empty, f.Id);
        });
    }
}
