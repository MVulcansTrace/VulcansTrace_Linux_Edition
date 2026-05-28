using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Tests.Helpers;

namespace VulcansTrace.Linux.Tests.Integration;

/// <summary>
/// Golden end-to-end tests backed by realistic log fixtures.
/// These tests pin expected detector categories for known analyst scenarios.
/// </summary>
public sealed class GoldenScenarioIntegrationTests
{
    private readonly SentryAnalyzer _analyzer = SentryAnalyzerFactory.CreateFull();

    [Fact]
    public void Analyze_GoldenCompromiseTimeline_DetectsExpectedIncidentCategories()
    {
        var result = AnalyzeSample("golden-compromise-timeline.log", IntensityLevel.Medium);

        Assert.Equal(38, result.TotalLines);
        Assert.Equal(38, result.ParsedLines);
        Assert.Equal(0, result.ParseErrorCount);
        Assert.Empty(result.Warnings);

        // Beaconing is intentionally omitted: when the same tuple triggers both
        // Beaconing and C2Channel detectors, the deduplication step absorbs the
        // Beaconing finding into the higher-severity C2Channel finding.
        // Novelty is omitted at Medium intensity: NoveltyDetector produces
        // Severity.Low findings, which are filtered out by MinSeverityToShow (Medium).
        string[] expectedCategories =
        [
            "C2Channel",
            "FlagAnomaly",
            "InterfaceHopping",
            "LateralMovement",
            "MacSpoofing",
            "PolicyViolation",
            "PortScan",
            "PrivilegeEscalation",
            "UnusualPacketSize"
        ];

        foreach (var category in expectedCategories)
        {
            Assert.Contains(result.Findings, finding => finding.Category == category);
        }
    }

    [Fact]
    public void Analyze_GoldenCompromiseTimeline_EscalatesCorrelatedLinuxEvasion()
    {
        var result = AnalyzeSample("golden-compromise-timeline.log", IntensityLevel.Medium);

        Assert.Contains(result.Findings, finding =>
            finding.Category == "MacSpoofing" &&
            finding.SourceHost == "10.0.0.77" &&
            finding.Severity == Severity.Critical);

        Assert.Contains(result.Findings, finding =>
            finding.Category == "InterfaceHopping" &&
            finding.SourceHost == "10.0.0.77" &&
            finding.Severity == Severity.Critical);
    }

    [Fact]
    public void Analyze_MixedPrefixIptablesLog_ParsesFirewallLinesAndPreservesWarnings()
    {
        var result = AnalyzeSample("iptables-mixed-prefixes.log", IntensityLevel.Medium);

        Assert.Equal(18, result.TotalLines);
        Assert.Equal(16, result.ParsedLines);
        Assert.Equal(0, result.ParseErrorCount);
        Assert.Equal(1, result.SkippedLineCount);
        Assert.Equal(2, result.Warnings.Count);
        Assert.Contains(result.Warnings, w => w.Contains("12 callbacks"));
        Assert.Contains(result.Warnings, w => w.Contains("skipped"));

        Assert.Contains(result.Findings, finding => finding.Category == "PortScan");
        Assert.Contains(result.Findings, finding => finding.Category == "FlagAnomaly");
        Assert.Contains(result.Findings, finding => finding.Category == "PrivilegeEscalation");
    }

    [Fact]
    public void Analyze_MixedPrefixIptablesLog_IgnoresNonFirewallNoise()
    {
        var result = AnalyzeSample("iptables-mixed-prefixes.log", IntensityLevel.Medium);

        Assert.DoesNotContain(result.ParseErrors, error => error.Contains("health check", StringComparison.OrdinalIgnoreCase));
        Assert.All(result.Entries, entry => Assert.Equal(LogFormat.Iptables, entry.LogFormat));
    }

    private AnalysisResult AnalyzeSample(string fileName, IntensityLevel intensity)
    {
        var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "Real", "Samples", fileName);
        var log = File.ReadAllText(path);
        return _analyzer.Analyze(log, intensity, CancellationToken.None);
    }
}
