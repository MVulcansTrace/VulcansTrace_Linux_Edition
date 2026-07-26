using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RiskScorecardBuilderTests
{
    private readonly RiskScorecardBuilder _builder = new();

    [Fact]
    public void Build_EmptyFindings_ReturnsNull()
    {
        var scorecard = _builder.Build(Array.Empty<Finding>());
        Assert.Null(scorecard);
    }

    [Fact]
    public void Build_NullFindings_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _builder.Build(null!));
    }

    [Fact]
    public void Build_OnlyInfoFindings_ReturnsPerfectScore()
    {
        var findings = new[]
        {
            CreateFinding(Severity.Info, "PortScan"),
            CreateFinding(Severity.Info, "Beaconing")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(100.0, scorecard.NumericScore);
        Assert.Equal("A", scorecard.LetterGrade);
        Assert.Equal("Low", scorecard.SummaryStatus);
        Assert.Equal(0, scorecard.TotalFindings); // Info findings are not risk-relevant
        Assert.Empty(scorecard.ByCategory); // Info contributes no deduction, so categories are excluded
    }

    [Fact]
    public void Build_SingleCritical_ReturnsCorrectScore()
    {
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "PortScan")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // Capped: Critical load 20 damped against cap 35 -> 15.2 deduction -> 84.8 (B)
        Assert.Equal(84.8, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
        Assert.Equal("Moderate", scorecard.SummaryStatus);
        Assert.Single(scorecard.ByCategory);
        Assert.Equal("PortScan", scorecard.ByCategory[0].Category);
        Assert.Equal(20.0, scorecard.ByCategory[0].TotalDeduction);
    }

    [Fact]
    public void Build_SingleHigh_ReturnsCorrectScore()
    {
        var findings = new[]
        {
            CreateFinding(Severity.High, "LateralMovement")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // Capped: High load 15 damped against cap 22 -> 10.9 deduction -> 89.1 (B)
        Assert.Equal(89.1, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
        Assert.Equal(15.0, scorecard.ByCategory[0].TotalDeduction);
    }

    [Fact]
    public void Build_MultipleSeverities_ReturnsCorrectScore()
    {
        // Capped: C(15.2) + H(10.9) + M(6.8) = 32.9 damped deduction -> 67.1 score -> D
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "PortScan"),
            CreateFinding(Severity.High, "Beaconing"),
            CreateFinding(Severity.Medium, "Flood")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(67.1, scorecard.NumericScore);
        Assert.Equal("D", scorecard.LetterGrade);
        Assert.Equal("High", scorecard.SummaryStatus);
    }

    [Fact]
    public void Build_ManyCriticals_NotClampedToZero()
    {
        // 6 * Critical (raw load 120) is damped by the Critical cap (35) to ~33.9 -> 66.1 (D), not 0.
        // This is the headline fix: a finding-heavy audit no longer reads as a hopeless "F".
        var findings = Enumerable.Range(0, 6)
            .Select(_ => CreateFinding(Severity.Critical, "PortScan"))
            .ToArray();

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(66.1, scorecard.NumericScore);
        Assert.Equal("D", scorecard.LetterGrade);
    }

    [Fact]
    public void Build_Saturated_ExposesTotalDeductionAndFlag()
    {
        // 6 * Critical (raw load 120) damped to ~33.9 -> score 66.1, but the raw deduction and a
        // saturation flag must still be surfaced so the dampened grade isn't misread as unconditionally clean.
        var findings = Enumerable.Range(0, 6)
            .Select(_ => CreateFinding(Severity.Critical, "PortScan"))
            .ToArray();

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(66.1, scorecard.NumericScore);
        Assert.Equal(120.0, scorecard.TotalDeduction);
        Assert.True(scorecard.IsSaturated);
    }

    [Fact]
    public void Build_NotSaturated_TotalDeductionEqualsSumAndFlagFalse()
    {
        // Critical (20) + High (15) = 35 raw, damped to 26.1 -> 73.9 score; caps shave only 8.9 (< 10), not saturated
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "PortScan"),
            CreateFinding(Severity.High, "Beaconing")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(73.9, scorecard.NumericScore);
        Assert.Equal(35.0, scorecard.TotalDeduction);
        Assert.False(scorecard.IsSaturated);
    }

    [Fact]
    public void Build_WithCisControlWeight_AppliesMultiplier()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.Critical,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1",
                ShortDescription = "Scan",
                Details = "Details",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M", ControlWeight = 2.0 }
                }
            }
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // Capped: Critical load 40 (weight 2.0) damped against cap 35 -> 23.8 -> 76.2 (C)
        Assert.Equal(76.2, scorecard.NumericScore);
        Assert.Equal("C", scorecard.LetterGrade);
        Assert.Equal(40.0, scorecard.ByCategory[0].TotalDeduction);
    }

    [Fact]
    public void Build_MultipleCisMappings_AveragesWeights()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.High,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1",
                ShortDescription = "Scan",
                Details = "Details",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "A", WhyItMatters = "M", ControlWeight = 1.0 },
                    new CisBenchmarkMapping { ControlId = "CIS 4.2", ControlName = "B", WhyItMatters = "M", ControlWeight = 3.0 }
                }
            }
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // Capped: High load 30 damped against cap 22 -> 16.4 -> 83.6 (B)
        Assert.Equal(83.6, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
    }

    [Fact]
    public void Build_MaxValueControlWeight_FallsBackToOne()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.Critical,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1",
                ShortDescription = "Scan",
                Details = "Details",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M", ControlWeight = double.MaxValue }
                }
            }
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // double.MaxValue falls back to 1.0, so Critical load 20 damped against cap 35 -> 15.2 -> 84.8 (B)
        Assert.Equal(84.8, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
        Assert.Equal(20.0, scorecard.ByCategory[0].TotalDeduction);
        Assert.True(double.IsFinite(scorecard.ByCategory[0].TotalDeduction));
    }

    [Fact]
    public void Build_ZeroControlWeight_FallsBackToOne()
    {
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.Critical,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1",
                ShortDescription = "Scan",
                Details = "Details",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M", ControlWeight = 0.0 }
                }
            }
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        // Weight 0.0 falls back to 1.0, so Critical load 20 damped against cap 35 -> 15.2 -> 84.8 (B)
        Assert.Equal(84.8, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
        Assert.Equal(20.0, scorecard.ByCategory[0].TotalDeduction);
    }

    [Fact]
    public void Build_ByCategoryOrderedByDeduction()
    {
        var findings = new[]
        {
            CreateFinding(Severity.Low, "Flood"),       // 5 deduction
            CreateFinding(Severity.Critical, "PortScan"), // 20 deduction
            CreateFinding(Severity.Medium, "Beaconing")   // 10 deduction
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(3, scorecard.ByCategory.Count);
        Assert.Equal("PortScan", scorecard.ByCategory[0].Category);   // 20
        Assert.Equal("Beaconing", scorecard.ByCategory[1].Category);  // 10
        Assert.Equal("Flood", scorecard.ByCategory[2].Category);      // 5
    }

    [Fact]
    public void Build_AverageSeverityCalculatedCorrectly()
    {
        var findings = new[]
        {
            CreateFinding(Severity.High, "PortScan"),
            CreateFinding(Severity.Low, "PortScan")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Single(scorecard.ByCategory);
        Assert.Equal(2.0, scorecard.ByCategory[0].AverageSeverity); // (3 + 1) / 2
    }

    [Fact]
    public void Build_RawScoreBelowThreshold_RoundsUpButKeepsLowerGrade()
    {
        // A single Medium finding with weight 2.17 produces a raw tier load of 21.7, which the Medium
        // cap (12) damps to ~10.0 -> raw score ~89.97. The grade must come from raw 89.97 (B), not
        // from the rounded display value 90.0 (A).
        var findings = new[]
        {
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.Medium,
                SourceHost = "10.0.0.1",
                Target = "192.168.1.1",
                ShortDescription = "Scan",
                Details = "Details",
                CisMappings = new[]
                {
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M", ControlWeight = 2.17 }
                }
            }
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(90.0, scorecard.NumericScore); // rounds up for display
        Assert.Equal("B", scorecard.LetterGrade);   // grade from raw 89.95
        Assert.Equal("Moderate", scorecard.SummaryStatus);
    }

    [Fact]
    public void Build_GradeBoundaries_A()
    {
        // 90.0 should be A
        var findings = new[] { CreateFinding(Severity.Low, "Flood") }; // 5 deduction -> 95
        var scorecard = _builder.Build(findings);
        Assert.Equal("A", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_B()
    {
        // 80.0 should be B
        var findings = new[] { CreateFinding(Severity.Critical, "Flood") }; // 20 deduction -> 80
        var scorecard = _builder.Build(findings);
        Assert.Equal("B", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_C()
    {
        // Capped: C(15.2) + H(10.9) = 26.1 damped -> 73.9 (C)
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.High, "Flood")
        };
        var scorecard = _builder.Build(findings);
        Assert.Equal("C", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_D()
    {
        // Capped: C(15.2) + H(10.9) + M(6.8) = 32.9 damped -> 67.1 (D)
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.Medium, "Flood")
        };
        var scorecard = _builder.Build(findings);
        Assert.Equal("D", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_F()
    {
        // Reaching F (<60) needs near-saturated Critical AND High tiers: 5 C (load 100 -> 33.0) +
        // 5 H (load 75 -> 21.3) = 54.3 damped -> 45.7 (F). Criticals alone can't get there (cap 35 -> floor 65).
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.High, "Flood")
        };
        var scorecard = _builder.Build(findings);
        Assert.Equal("F", scorecard!.LetterGrade);
    }

    private static Finding CreateFinding(Severity severity, string category)
    {
        return new Finding
        {
            Category = category,
            Severity = severity,
            SourceHost = "10.0.0.1",
            Target = "192.168.1.1",
            ShortDescription = "Test finding",
            Details = "Test details"
        };
    }
}
