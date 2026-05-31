using System;
using System.Collections.Generic;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class ComplianceScorecardViewModelTests
{
    [Fact]
    public void LoadScorecard_Null_ClearsData()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(null);

        Assert.False(vm.HasData);
        Assert.Equal(0, vm.OverallScore);
        Assert.Equal("—", vm.SummaryStatus);
    }

    [Fact]
    public void LoadScorecard_NoTrend_ShowsNoTrendData()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 85.0,
            SummaryStatus = "Warn",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = Array.Empty<ComplianceTrendPoint>()
        });

        Assert.True(vm.HasData);
        Assert.Equal(85.0, vm.OverallScore);
        Assert.Equal("Warn", vm.SummaryStatus);
        Assert.Equal("No trend data yet", vm.TrendDirection);
        Assert.Empty(vm.TrendArrow);
        Assert.Empty(vm.TrendPoints);
    }

    [Fact]
    public void LoadScorecard_SingleTrend_ComparesCurrentAgainstPrior()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 90.0,
            SummaryStatus = "Pass",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 80.0
                }
            }
        });

        Assert.True(vm.HasData);
        Assert.Equal("Improving (+10.0%)", vm.TrendDirection);
        Assert.Equal("↗", vm.TrendArrow);
        Assert.Single(vm.TrendPoints);
        Assert.Equal(80.0, vm.TrendPoints[0].OverallScore);
        Assert.Equal(60.0, vm.TrendPoints[0].BarHeight); // single point = full height
    }

    [Fact]
    public void LoadScorecard_MultipleTrend_ComparesCurrentAgainstMostRecentPrior()
    {
        // This is the key bug fix: trend contains [older, newer] previous audits.
        // The direction should be current (95%) vs most recent prior (85%), NOT 85% vs 75%.
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 95.0,
            SummaryStatus = "Pass",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-2),
                    OverallScore = 75.0
                },
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 85.0
                }
            }
        });

        Assert.True(vm.HasData);
        // Current 95.0 vs prior 85.0 = +10.0 improving
        Assert.Equal("Improving (+10.0%)", vm.TrendDirection);
        Assert.Equal("↗", vm.TrendArrow);
        Assert.Equal(2, vm.TrendPoints.Count);
        Assert.Equal(75.0, vm.TrendPoints[0].OverallScore);
        Assert.Equal(85.0, vm.TrendPoints[1].OverallScore);
        // Bar heights scale relative to max (85): 75/85*60 = 52.9, 85/85*60 = 60
        Assert.Equal(52.9, vm.TrendPoints[0].BarHeight, precision: 1);
        Assert.Equal(60.0, vm.TrendPoints[1].BarHeight);
    }

    [Fact]
    public void LoadScorecard_DecliningTrend_ShowsDeclining()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 70.0,
            SummaryStatus = "Fail",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 85.0
                }
            }
        });

        Assert.Equal("Declining (-15.0%)", vm.TrendDirection);
        Assert.Equal("↘", vm.TrendArrow);
    }

    [Fact]
    public void LoadScorecard_StableTrend_ShowsStable()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 85.2,
            SummaryStatus = "Pass",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 85.0
                }
            }
        });

        Assert.Equal("Stable", vm.TrendDirection);
        Assert.Equal("→", vm.TrendArrow);
    }

    [Fact]
    public void LoadScorecard_ExactlyHalfPercentImproving_ShowsStable()
    {
        // Boundary: delta = +0.5 is NOT "Improving", it's "Stable"
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 85.5,
            SummaryStatus = "Pass",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 85.0
                }
            }
        });

        Assert.Equal("Stable", vm.TrendDirection);
        Assert.Equal("→", vm.TrendArrow);
    }

    [Fact]
    public void LoadScorecard_ExactlyHalfPercentDeclining_ShowsStable()
    {
        // Boundary: delta = -0.5 is NOT "Declining", it's "Stable"
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 84.5,
            SummaryStatus = "Pass",
            FamilyScores = Array.Empty<ControlFamilyScore>(),
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = DateTime.UtcNow.AddDays(-1),
                    OverallScore = 85.0
                }
            }
        });

        Assert.Equal("Stable", vm.TrendDirection);
        Assert.Equal("→", vm.TrendArrow);
    }

    [Fact]
    public void LoadScorecard_FamilyScores_Populated()
    {
        var vm = new ComplianceScorecardViewModel();
        vm.LoadScorecard(new ComplianceScorecard
        {
            OverallScore = 85.0,
            SummaryStatus = "Warn",
            FamilyScores = new[]
            {
                new ControlFamilyScore
                {
                    FamilyId = "4",
                    FamilyName = "Logging and Auditing",
                    TotalControls = 5,
                    PassedControls = 4,
                    ScorePercentage = 80.0,
                    Status = "Warn"
                }
            },
            Trend = Array.Empty<ComplianceTrendPoint>()
        });

        Assert.True(vm.HasData);
        Assert.Single(vm.FamilyScores);
        Assert.Equal("Logging and Auditing", vm.FamilyScores[0].FamilyName);
        Assert.Equal("Warn", vm.FamilyScores[0].Status);
    }
}
