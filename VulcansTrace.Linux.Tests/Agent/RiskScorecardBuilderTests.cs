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
        Assert.Equal(80.0, scorecard.NumericScore);
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
        Assert.Equal(85.0, scorecard.NumericScore);
        Assert.Equal("B", scorecard.LetterGrade);
        Assert.Equal(15.0, scorecard.ByCategory[0].TotalDeduction);
    }

    [Fact]
    public void Build_MultipleSeverities_ReturnsCorrectScore()
    {
        // Critical (20) + High (15) + Medium (10) = 45 deduction -> 55 score -> F
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "PortScan"),
            CreateFinding(Severity.High, "Beaconing"),
            CreateFinding(Severity.Medium, "Flood")
        };

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(55.0, scorecard.NumericScore);
        Assert.Equal("F", scorecard.LetterGrade);
        Assert.Equal("Severe", scorecard.SummaryStatus);
    }

    [Fact]
    public void Build_ClampedAtZero()
    {
        // 6 * Critical (20) = 120 deduction, clamped to 0
        var findings = Enumerable.Range(0, 6)
            .Select(_ => CreateFinding(Severity.Critical, "PortScan"))
            .ToArray();

        var scorecard = _builder.Build(findings);

        Assert.NotNull(scorecard);
        Assert.Equal(0.0, scorecard.NumericScore);
        Assert.Equal("F", scorecard.LetterGrade);
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
        // Critical (4) * 5 * weight (2.0) = 40 deduction -> 60 score -> D
        Assert.Equal(60.0, scorecard.NumericScore);
        Assert.Equal("D", scorecard.LetterGrade);
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
        // High (3) * 5 * avg weight (2.0) = 30 deduction -> 70 score -> C
        Assert.Equal(70.0, scorecard.NumericScore);
        Assert.Equal("C", scorecard.LetterGrade);
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
        // double.MaxValue should fall back to 1.0, so Critical = 4 * 5 * 1 = 20 deduction -> 80 score -> B
        Assert.Equal(80.0, scorecard.NumericScore);
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
        // Weight 0.0 should fall back to 1.0, so Critical = 4 * 5 * 1 = 20 deduction -> 80 score -> B
        Assert.Equal(80.0, scorecard.NumericScore);
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
        // A Medium finding with weight 1.005 produces deduction 10.05 → raw score 89.95
        // Grade must be computed from raw 89.95 (B), not from rounded 90.0 (A)
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
                    new CisBenchmarkMapping { ControlId = "CIS 4.1", ControlName = "Test", WhyItMatters = "M", ControlWeight = 1.005 }
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
        // 70.0 should be C
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Low, "Flood") // 20 + 5 = 25 -> 75, need 30 -> 70
        };
        // Actually 75 is C. Let's do 2 Critical = 40 -> 60 = D. Need exact 70.
        // High (15) + Medium (10) = 25 -> 75 (C)
        // High (15) + High (15) = 30 -> 70 (C)
        var findings2 = new[]
        {
            CreateFinding(Severity.High, "Flood"),
            CreateFinding(Severity.High, "Flood")
        };
        var scorecard = _builder.Build(findings2);
        Assert.Equal("C", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_D()
    {
        // 60.0 should be D
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.High, "Flood") // 20 + 15 = 35 -> 65 (D)
        };
        var scorecard = _builder.Build(findings);
        Assert.Equal("D", scorecard!.LetterGrade);
    }

    [Fact]
    public void Build_GradeBoundaries_F()
    {
        // < 60 should be F
        var findings = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood") // 40 -> 60 is D, need more
        };
        var findings2 = new[]
        {
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Critical, "Flood"),
            CreateFinding(Severity.Low, "Flood") // 45 -> 55 (F)
        };
        var scorecard = _builder.Build(findings2);
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
