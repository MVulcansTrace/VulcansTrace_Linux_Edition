using System;
using System.Collections.Generic;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class ComplianceTrendAnalyzerTests
{
    [Fact]
    public void ComputeDirection_EmptyTrend_ReturnsNoTrendData()
    {
        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(
            Array.Empty<ComplianceTrendPoint>(), 85.0);

        Assert.Equal("No trend data yet", direction);
        Assert.Empty(arrow);
    }

    [Fact]
    public void ComputeDirection_Improving_ReturnsImproving()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 80.0 }
        };

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 90.0);

        Assert.Equal("Improving (+10.0%)", direction);
        Assert.Equal("↗", arrow);
    }

    [Fact]
    public void ComputeDirection_Declining_ReturnsDeclining()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 90.0 }
        };

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 75.0);

        Assert.Equal("Declining (-15.0%)", direction);
        Assert.Equal("↘", arrow);
    }

    [Fact]
    public void ComputeDirection_Stable_ReturnsStable()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 85.0 }
        };

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 85.2);

        Assert.Equal("Stable", direction);
        Assert.Equal("→", arrow);
    }

    [Fact]
    public void ComputeDirection_ExactlyPlusHalf_ReturnsStable()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 85.0 }
        };

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 85.5);

        Assert.Equal("Stable", direction);
        Assert.Equal("→", arrow);
    }

    [Fact]
    public void ComputeDirection_ExactlyMinusHalf_ReturnsStable()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 85.0 }
        };

        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 84.5);

        Assert.Equal("Stable", direction);
        Assert.Equal("→", arrow);
    }

    [Fact]
    public void ComputeDirection_UsesMostRecentPrior()
    {
        var trend = new List<ComplianceTrendPoint>
        {
            new() { Timestamp = DateTime.UtcNow.AddDays(-2), OverallScore = 75.0 },
            new() { Timestamp = DateTime.UtcNow.AddDays(-1), OverallScore = 85.0 }
        };

        // Current 95 vs most recent prior 85 = +10 improving (not vs 75)
        var (direction, arrow) = ComplianceTrendAnalyzer.ComputeDirection(trend, 95.0);

        Assert.Equal("Improving (+10.0%)", direction);
        Assert.Equal("↗", arrow);
    }
}
