using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Detectors;
using Xunit;

namespace VulcansTrace.Linux.Tests.Engine;

public class DetectionResultTests
{
    [Fact]
    public void Constructor_WithNullFindings_CoalescesToEmpty()
    {
        var result = new DetectionResult(null!, Array.Empty<string>());

        Assert.NotNull(result.Findings);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Constructor_WithNullWarnings_CoalescesToEmpty()
    {
        var result = new DetectionResult(Array.Empty<Finding>(), null!);

        Assert.NotNull(result.Warnings);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Constructor_WithBothNull_CoalescesBothToEmpty()
    {
        var result = new DetectionResult(null!, null!);

        Assert.NotNull(result.Findings);
        Assert.Empty(result.Findings);
        Assert.NotNull(result.Warnings);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Constructor_SingleArg_NullFindings_CoalescesToEmpty()
    {
        var result = new DetectionResult(null!);

        Assert.NotNull(result.Findings);
        Assert.Empty(result.Findings);
        Assert.NotNull(result.Warnings);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Empty_StaticProperty_HasNoFindingsOrWarnings()
    {
        Assert.Empty(DetectionResult.Empty.Findings);
        Assert.Empty(DetectionResult.Empty.Warnings);
    }

    [Fact]
    public void Constructor_WithValidFindings_PreservesFindings()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.High,
                SourceHost = "192.168.1.1",
                Target = "10.0.0.1",
                ShortDescription = "Scan detected",
                Details = "Details"
            }
        };

        var result = new DetectionResult(findings);

        Assert.Single(result.Findings);
        Assert.Equal("PortScan", result.Findings[0].Category);
    }

    [Fact]
    public void Constructor_WithValidWarnings_PreservesWarnings()
    {
        var warnings = new[] { "Warning 1", "Warning 2" };
        var result = new DetectionResult(Array.Empty<Finding>(), warnings);

        Assert.Equal(2, result.Warnings.Count);
        Assert.Equal("Warning 1", result.Warnings[0]);
        Assert.Equal("Warning 2", result.Warnings[1]);
    }
}
