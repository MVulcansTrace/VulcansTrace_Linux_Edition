using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Tests.Helpers;
using Xunit;

namespace VulcansTrace.Linux.Tests.Detectors.Baseline;

public class PolicyViolationDetectorTests
{
    private readonly PolicyViolationDetector _detector = new();
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void Detect_PolicyViolationDisallowedPort_ReturnsFinding()
    {
        // Arrange - Internal to external on disallowed port (FTP)
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=21";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 25 } // FTP, Telnet, SMTP
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal(FindingCategories.PolicyViolation, findings[0].Category);
        Assert.Equal(Severity.High, findings[0].Severity);
        Assert.Equal("192.168.1.100", findings[0].SourceHost);
        Assert.Contains("8.8.8.8:21", findings[0].Target);
    }

    [Fact]
    public void Detect_PolicyViolationAllowedPort_ReturnsNoFindings()
    {
        // Arrange - Internal to external on allowed port (HTTP)
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=80";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21, 23, 25 } // FTP, Telnet, SMTP
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PolicyViolationInternalToInternal_ReturnsNoFindings()
    {
        // Arrange - Internal to internal traffic (should be ignored)
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=21";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }

    [Fact]
    public void Detect_PolicyViolationMultipleDestinations_TargetShowsMultipleHosts()
    {
        // Arrange - Internal source connecting to multiple external destinations on disallowed port
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=21
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=1.1.1.1 PROTO=TCP SPT=54322 DPT=21
kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.100 DST=9.9.9.9 PROTO=TCP SPT=54323 DPT=21";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("multiple hosts:21", findings[0].Target);
        Assert.Contains("3 destination(s)", findings[0].Details);
    }

    [Fact]
    public void Detect_PolicyViolationSingleDestination_TargetShowsSpecificHost()
    {
        // Arrange - Internal source connecting to one external destination on disallowed port
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=21
kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=TCP SPT=54322 DPT=21";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Single(findings);
        Assert.Equal("8.8.8.8:21", findings[0].Target);
    }

    [Fact]
    public void Detect_PolicyViolationExternalToInternal_ReturnsNoFindings()
    {
        // Arrange - External to internal (reverse direction, should be ignored)
        var log = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=8.8.8.8 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=21";
        var events = _normalizer.Normalize(log).Events;
        var profile = new AnalysisProfile
        {
            EnablePolicy = true,
            DisallowedOutboundPorts = new[] { 21 }
        };

        // Act
        var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

        // Assert
        Assert.Empty(findings);
    }
}
