using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class RiskScorecardFormatterTests
{
    private readonly RiskScorecardHtmlFormatter _htmlFormatter = new();
    private readonly RiskScorecardMarkdownFormatter _markdownFormatter = new();

    private static RiskScorecard SampleScorecard() => new()
    {
        NumericScore = 75.0,
        LetterGrade = "C",
        SummaryStatus = "High",
        TotalFindings = 3,
        ByCategory =
        [
            new CategoryRisk { Category = "PortScan", FindingCount = 2, AverageSeverity = 3.0, TotalDeduction = 30.0 },
            new CategoryRisk { Category = "Beaconing", FindingCount = 1, AverageSeverity = 2.0, TotalDeduction = 10.0 }
        ]
    };

    [Fact]
    public void ToHtml_NullScorecard_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _htmlFormatter.ToHtml(null!));
    }

    [Fact]
    public void ToMarkdown_NullScorecard_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _markdownFormatter.ToMarkdown(null!));
    }

    [Fact]
    public void ToHtml_ContainsGradeAndScore()
    {
        var html = _htmlFormatter.ToHtml(SampleScorecard());

        Assert.Contains("Risk Scorecard", html);
        Assert.Contains("C", html);
        Assert.Contains("75.0", html);
        Assert.Contains("High", html);
    }

    [Fact]
    public void ToHtml_ContainsCategoryData()
    {
        var html = _htmlFormatter.ToHtml(SampleScorecard());

        Assert.Contains("PortScan", html);
        Assert.Contains("Beaconing", html);
        Assert.Contains("30.0", html);
        Assert.Contains("10.0", html);
    }

    [Fact]
    public void ToHtml_EmptyCategories_NoTable()
    {
        var scorecard = SampleScorecard() with { ByCategory = [] };
        var html = _htmlFormatter.ToHtml(scorecard);

        Assert.Contains("Risk Scorecard", html);
        Assert.DoesNotContain("<table>", html);
    }

    [Fact]
    public void ToMarkdown_ContainsGradeAndScore()
    {
        var md = _markdownFormatter.ToMarkdown(SampleScorecard());

        Assert.Contains("# Risk Scorecard", md);
        Assert.Contains("C", md);
        Assert.Contains("75.0", md);
        Assert.Contains("High", md);
    }

    [Fact]
    public void ToMarkdown_ContainsCategoryData()
    {
        var md = _markdownFormatter.ToMarkdown(SampleScorecard());

        Assert.Contains("PortScan", md);
        Assert.Contains("Beaconing", md);
        Assert.Contains("30.0", md);
        Assert.Contains("10.0", md);
    }

    [Fact]
    public void ToMarkdown_EmptyCategories_NoTable()
    {
        var scorecard = SampleScorecard() with { ByCategory = [] };
        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.Contains("# Risk Scorecard", md);
        Assert.DoesNotContain("| Category |", md);
    }
}
