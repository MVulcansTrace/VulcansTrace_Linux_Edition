using System;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class RiskScorecardViewModelTests
{
    [AvaloniaFact]
    public void LoadScorecard_Null_ClearsData()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(null);

        Assert.False(vm.HasData);
        Assert.Equal(0, vm.NumericScore);
        Assert.Equal(0, vm.TotalDeduction);
        Assert.False(vm.IsSaturated);
        Assert.Equal("—", vm.LetterGrade);
        Assert.Equal("—", vm.SummaryStatus);
        Assert.Equal("#64748b", vm.GradeColor);
        Assert.Equal("#1e293b", vm.GradeBackground);
        Assert.Empty(vm.ByCategory);
    }

    [AvaloniaFact]
    public void LoadScorecard_WithData_PopulatesProperties()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 72.5,
            TotalDeduction = 27.5,
            IsSaturated = false,
            LetterGrade = "C",
            SummaryStatus = "Elevated",
            TotalFindings = 3,
            ByCategory = new[]
            {
                new CategoryRisk { Category = "Port", FindingCount = 2, TotalDeduction = 15.0, AverageSeverity = 3.0 },
                new CategoryRisk { Category = "Firewall", FindingCount = 1, TotalDeduction = 12.5, AverageSeverity = 2.5 }
            }
        });

        Assert.True(vm.HasData);
        Assert.Equal(72.5, vm.NumericScore);
        Assert.Equal(27.5, vm.TotalDeduction);
        Assert.False(vm.IsSaturated);
        Assert.Equal("C", vm.LetterGrade);
        Assert.Equal("Elevated", vm.SummaryStatus);
        Assert.Equal(2, vm.ByCategory.Count);
        Assert.Equal("Port", vm.ByCategory[0].Category);
        Assert.Equal(2, vm.ByCategory[0].FindingCount);
        Assert.Equal("Firewall", vm.ByCategory[1].Category);
    }

    [AvaloniaFact]
    public void LoadScorecard_Saturated_CopiesTotalDeductionAndFlag()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 0.0,
            TotalDeduction = 125.0,
            IsSaturated = true,
            LetterGrade = "F",
            SummaryStatus = "Severe",
            TotalFindings = 12,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.True(vm.HasData);
        Assert.Equal(0.0, vm.NumericScore);
        Assert.Equal(125.0, vm.TotalDeduction);
        Assert.True(vm.IsSaturated);
    }

    [AvaloniaFact]
    public void LoadScorecard_GradeA_MapsGreenColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 95.0,
            LetterGrade = "A",
            SummaryStatus = "Low",
            TotalFindings = 0,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#34d399", vm.GradeColor);
        Assert.Equal("#064e3b", vm.GradeBackground);
    }

    [AvaloniaFact]
    public void LoadScorecard_GradeB_MapsBlueColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 85.0,
            LetterGrade = "B",
            SummaryStatus = "Moderate",
            TotalFindings = 1,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#60a5fa", vm.GradeColor);
        Assert.Equal("#1e3a8a", vm.GradeBackground);
    }

    [AvaloniaFact]
    public void LoadScorecard_GradeC_MapsYellowColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 75.0,
            LetterGrade = "C",
            SummaryStatus = "Elevated",
            TotalFindings = 2,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#fbbf24", vm.GradeColor);
        Assert.Equal("#451a03", vm.GradeBackground);
    }

    [AvaloniaFact]
    public void LoadScorecard_GradeD_MapsOrangeColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 65.0,
            LetterGrade = "D",
            SummaryStatus = "High",
            TotalFindings = 5,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#fb923c", vm.GradeColor);
        Assert.Equal("#431407", vm.GradeBackground);
    }

    [AvaloniaFact]
    public void LoadScorecard_GradeF_MapsRedColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 45.0,
            LetterGrade = "F",
            SummaryStatus = "Severe",
            TotalFindings = 10,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#f87171", vm.GradeColor);
        Assert.Equal("#450a0a", vm.GradeBackground);
    }

    [AvaloniaFact]
    public void LoadScorecard_Overwrite_ClearsPreviousCategories()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 85.0,
            LetterGrade = "B",
            SummaryStatus = "Moderate",
            TotalFindings = 2,
            ByCategory = new[]
            {
                new CategoryRisk { Category = "Port", FindingCount = 2, TotalDeduction = 10.0, AverageSeverity = 2.0 }
            }
        });

        Assert.Single(vm.ByCategory);

        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 95.0,
            LetterGrade = "A",
            SummaryStatus = "Low",
            TotalFindings = 0,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Empty(vm.ByCategory);
        Assert.Equal(95.0, vm.NumericScore);
        Assert.Equal("A", vm.LetterGrade);
    }

    [AvaloniaFact]
    public void LoadScorecard_UnknownGrade_MapsRedColors()
    {
        var vm = new RiskScorecardViewModel();
        vm.LoadScorecard(new RiskScorecard
        {
            NumericScore = 50.0,
            LetterGrade = "X",
            SummaryStatus = "Unknown",
            TotalFindings = 1,
            ByCategory = Array.Empty<CategoryRisk>()
        });

        Assert.Equal("#f87171", vm.GradeColor);
        Assert.Equal("#450a0a", vm.GradeBackground);
    }
}
