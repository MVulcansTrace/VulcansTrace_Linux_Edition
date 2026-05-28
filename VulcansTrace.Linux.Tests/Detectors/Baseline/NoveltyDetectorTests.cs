using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class NoveltyDetectorTests
{
    private readonly NoveltyDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_NoveltySingleConnection_ReturnsFinding()
    {
        // Arrange - External destination with only one connection
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=8080";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.Novelty, findings[0].Category);
        Assert.Equal(Severity.Low, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("8.8.8.8:8080", findings[0].Target);
    }

    [Fact]
    public void Detect_NoveltyMultipleConnections_ReturnsNoFindings()
    {
        // Arrange - External destination with multiple connections (not novel)
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=8080
	kernel: Jan 19 10:15:42 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54322 DPT=8080
	kernel: Jan 19 10:15:52 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54323 DPT=8080";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableNovelty = true
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_NoveltyDisabled_ReturnsNoFindings()
    {
        // Arrange
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=8080";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnableNovelty = false // Disabled
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }
}
