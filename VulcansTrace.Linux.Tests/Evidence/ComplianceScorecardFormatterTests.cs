using VulcansTrace.Linux.Core.Compliance;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class ComplianceScorecardFormatterTests
{
    private readonly ComplianceScorecardHtmlFormatter _htmlFormatter = new();
    private readonly ComplianceScorecardMarkdownFormatter _markdownFormatter = new();

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

    private static ComplianceScorecard CreateSampleScorecard()
    {
        return new ComplianceScorecard
        {
            OverallScore = 85.5,
            SummaryStatus = "Warn",
            FamilyScores = new[]
            {
                new ControlFamilyScore
                {
                    FamilyId = "3",
                    FamilyName = "Network Configuration",
                    TotalControls = 4,
                    PassedControls = 4,
                    FailedControls = 0,
                    CrashedControls = 0,
                    SuppressedControls = 0,
                    ScorePercentage = 100.0,
                    Status = "Pass"
                },
                new ControlFamilyScore
                {
                    FamilyId = "4",
                    FamilyName = "Logging and Auditing",
                    TotalControls = 5,
                    PassedControls = 3,
                    FailedControls = 2,
                    CrashedControls = 0,
                    SuppressedControls = 0,
                    ScorePercentage = 60.0,
                    Status = "Fail"
                }
            },
            Trend = new[]
            {
                new ComplianceTrendPoint
                {
                    Timestamp = new DateTime(2024, 1, 1, 10, 0, 0, DateTimeKind.Utc),
                    OverallScore = 75.0
                },
                new ComplianceTrendPoint
                {
                    Timestamp = new DateTime(2024, 1, 2, 10, 0, 0, DateTimeKind.Utc),
                    OverallScore = 85.5
                }
            }
        };
    }

    [Fact]
    public void ToHtml_ContainsOverallScore()
    {
        var scorecard = CreateSampleScorecard();
        var html = _htmlFormatter.ToHtml(scorecard);

        Assert.Contains("85.5%", html);
        Assert.Contains("CIS Compliance Scorecard", html);
    }

    [Fact]
    public void ToHtml_ContainsFamilyTable()
    {
        var scorecard = CreateSampleScorecard();
        var html = _htmlFormatter.ToHtml(scorecard);

        Assert.Contains("Network Configuration", html);
        Assert.Contains("Logging and Auditing", html);
        Assert.Contains("Pass", html);
        Assert.Contains("Fail", html);
    }

    [Fact]
    public void ToHtml_ContainsTrendSection()
    {
        var scorecard = CreateSampleScorecard();
        var html = _htmlFormatter.ToHtml(scorecard);

        Assert.Contains("Trend", html);
        Assert.Contains("75.0%", html);
        Assert.Contains("85.5%", html);
    }

    [Fact]
    public void ToHtml_EscapesContent()
    {
        var scorecard = new ComplianceScorecard
        {
            OverallScore = 100.0,
            SummaryStatus = "Pass",
            FamilyScores = new[]
            {
                new ControlFamilyScore
                {
                    FamilyId = "1",
                    FamilyName = "Test <script>alert(1)</script>",
                    TotalControls = 1,
                    PassedControls = 1,
                    ScorePercentage = 100.0,
                    Status = "Pass"
                }
            }
        };

        var html = _htmlFormatter.ToHtml(scorecard);

        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void ToMarkdown_ContainsOverallScore()
    {
        var scorecard = CreateSampleScorecard();
        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.Contains("85.5%", md);
        Assert.Contains("# CIS Compliance Scorecard", md);
    }

    [Fact]
    public void ToMarkdown_ContainsFamilyTable()
    {
        var scorecard = CreateSampleScorecard();
        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.Contains("Network Configuration", md);
        Assert.Contains("Logging and Auditing", md);
        Assert.Contains("|", md); // table pipes
    }

    [Fact]
    public void ToMarkdown_ContainsTrendSection()
    {
        var scorecard = CreateSampleScorecard();
        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.Contains("Trend", md);
        Assert.Contains("75.0%", md);
    }

    [Fact]
    public void ToMarkdown_EscapesPipes()
    {
        var scorecard = new ComplianceScorecard
        {
            OverallScore = 100.0,
            SummaryStatus = "Pass",
            FamilyScores = new[]
            {
                new ControlFamilyScore
                {
                    FamilyId = "1",
                    FamilyName = "Test | Pipe",
                    TotalControls = 1,
                    PassedControls = 1,
                    ScorePercentage = 100.0,
                    Status = "Pass"
                }
            }
        };

        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.Contains("Test \\| Pipe", md);
    }

    [Fact]
    public void ToMarkdown_EscapesTabsAndCarriageReturns()
    {
        var scorecard = new ComplianceScorecard
        {
            OverallScore = 100.0,
            SummaryStatus = "Pass",
            FamilyScores = new[]
            {
                new ControlFamilyScore
                {
                    FamilyId = "1",
                    FamilyName = "Test\tTab\rBareCR",
                    TotalControls = 1,
                    PassedControls = 1,
                    ScorePercentage = 100.0,
                    Status = "Pass"
                }
            }
        };

        var md = _markdownFormatter.ToMarkdown(scorecard);

        Assert.DoesNotContain("\t", md);
        Assert.DoesNotContain("\r", md);
        Assert.Contains("Test Tab BareCR", md);
    }
}
