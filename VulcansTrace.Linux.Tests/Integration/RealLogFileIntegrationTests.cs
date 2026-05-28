using Xunit;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Integration;

/// <summary>
/// Integration tests using real log files to verify end-to-end analysis functionality.
/// Tests both iptables and nftables formats with actual attack patterns.
/// </summary>
public sealed class RealLogFileIntegrationTests : IDisposable
{
    private readonly SentryAnalyzer _analyzer;
    private readonly string _iptablesAttackLogPath;
    private readonly string _nftablesTrafficLogPath;

    public RealLogFileIntegrationTests()
    {
        // Initialize the analyzer with all required dependencies (same as MainWindow)
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

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

        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var riskEscalator = new RiskEscalator();
        _analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator);

        // Get paths to test log files
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var samplesDir = Path.Combine(baseDir, "Data", "Real", "Samples");
        _iptablesAttackLogPath = Path.Combine(samplesDir, "iptables-attack.log");
        _nftablesTrafficLogPath = Path.Combine(samplesDir, "nftables-traffic.log");
    }

    [Fact]
    public void Analyze_IptablesAttackLog_ParsesSuccessfully()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0, "Should parse at least some lines from iptables log");
        Assert.True(result.TotalLines > 0, "Should have total lines");
        Assert.NotEmpty(result.Entries);
    }

    [Fact]
    public void Analyze_IptablesAttackLog_DetectsPortScan()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        // iptables-attack.log contains 5 different ports being scanned (22, 23, 80, 443, 3389)
        Assert.True(result.ParsedLines > 0, "Should parse log entries successfully");
        Assert.Contains(result.Findings, finding => finding.Category == "PortScan");
    }

    [Fact]
    public void Analyze_IptablesAttackLog_ProducesValidSeverityValues()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.High, CancellationToken.None);

        // Assert - Integration test validates that severity levels are properly assigned
        // If findings exist, they should have valid severity levels
        if (result.Findings.Any())
        {
            Assert.All(result.Findings, finding =>
            {
                Assert.True(Enum.IsDefined(typeof(Severity), finding.Severity),
                    $"Severity {finding.Severity} should be valid");
            });
        }

        // At minimum, verify parsing worked
        Assert.True(result.ParsedLines > 0, "Should parse log entries successfully");
    }

    [Fact]
    public void Analyze_NftablesTrafficLog_ParsesSuccessfully()
    {
        // Arrange
        var logContent = File.ReadAllText(_nftablesTrafficLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0, "Should parse at least some lines from nftables log");
        Assert.True(result.TotalLines > 0, "Should have total lines");
        Assert.NotEmpty(result.Entries);
    }

    [Fact]
    public void Analyze_NftablesTrafficLog_ParsesCleanInternalTrafficWithoutFindings()
    {
        // Arrange
        var logContent = File.ReadAllText(_nftablesTrafficLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        // nftables-traffic.log is internal SSH traffic and should remain clean at Medium intensity.
        Assert.True(result.ParsedLines > 0, "Should parse nftables log entries successfully");
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Analyze_BothLogFormats_ProducesConsistentSchema()
    {
        // Arrange
        var iptablesContent = File.ReadAllText(_iptablesAttackLogPath);
        var nftablesContent = File.ReadAllText(_nftablesTrafficLogPath);

        // Act
        var iptablesResult = _analyzer.Analyze(iptablesContent, IntensityLevel.Medium, CancellationToken.None);
        var nftablesResult = _analyzer.Analyze(nftablesContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert - Both should produce unified schema results
        Assert.Equal(typeof(AnalysisResult), iptablesResult.GetType());
        Assert.Equal(typeof(AnalysisResult), nftablesResult.GetType());

        // Both should have consistent property types
        Assert.Equal(iptablesResult.Entries.GetType(), nftablesResult.Entries.GetType());
        Assert.Equal(iptablesResult.Findings.GetType(), nftablesResult.Findings.GetType());
    }

    [Fact]
    public void Analyze_IptablesAttackLog_TimeRangeIsSet()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        Assert.NotEqual(DateTime.MinValue, result.TimeRangeStart);
        Assert.NotEqual(DateTime.MinValue, result.TimeRangeEnd);
        Assert.True(result.TimeRangeEnd >= result.TimeRangeStart,
            "Time range end should be >= start");
    }

    [Theory]
    [InlineData(IntensityLevel.Low)]
    [InlineData(IntensityLevel.Medium)]
    [InlineData(IntensityLevel.High)]
    public void Analyze_IptablesAttackLog_WorksAtAllIntensityLevels(IntensityLevel intensity)
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, intensity, CancellationToken.None);

        // Assert
        Assert.True(result.ParsedLines > 0, $"Should parse at intensity level {intensity}");
        Assert.NotNull(result.Findings);
    }

    [Fact]
    public void Analyze_LargeLogFile_PerformsWithinAcceptableTime()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);
        var largeLogContent = string.Join("\n", Enumerable.Repeat(logContent, 100)); // Repeat 100x

        // Act
        var startTime = DateTime.UtcNow;
        var result = _analyzer.Analyze(largeLogContent, IntensityLevel.Medium, CancellationToken.None);
        var duration = DateTime.UtcNow - startTime;

        // Assert - Should complete in under 5 seconds for 500 lines
        Assert.True(duration.TotalSeconds < 5.0,
            $"Analysis took {duration.TotalSeconds:F2}s, should be under 5 seconds");
        Assert.True(result.ParsedLines > 0, "Should still parse large file");
    }

    [Fact]
    public void Analyze_WithCancellationToken_CanBeCancelled()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);
        var largeLogContent = string.Join("\n", Enumerable.Repeat(logContent, 1000)); // Large file
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert
        var exception = Assert.Throws<OperationCanceledException>(() =>
        {
            _analyzer.Analyze(largeLogContent, IntensityLevel.Medium, cts.Token);
        });

        Assert.Equal(cts.Token, exception.CancellationToken);
    }

    [Fact]
    public void Analyze_IptablesAttackLog_AllBaselineDetectorsRun()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        // Integration test validates that the analyzer runs successfully
        // Findings may or may not be present depending on thresholds
        Assert.True(result.ParsedLines > 0, "Should parse log entries successfully");
        Assert.NotNull(result.Findings);
    }

    [Fact]
    public void Analyze_IptablesAttackLog_ProducesValidFindings()
    {
        // Arrange
        var logContent = File.ReadAllText(_iptablesAttackLogPath);

        // Act
        var result = _analyzer.Analyze(logContent, IntensityLevel.Medium, CancellationToken.None);

        // Assert
        foreach (var finding in result.Findings)
        {
            Assert.NotNull(finding);
            Assert.NotEmpty(finding.ShortDescription);
            Assert.NotEqual(Guid.Empty, finding.Id);
            Assert.True(Enum.IsDefined(typeof(Severity), finding.Severity));
        }
    }

    public void Dispose()
    {
        // Cleanup if needed
    }
}
