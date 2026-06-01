using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentReportGeneratorTests
{
    private readonly AgentReportGenerator _generator = new();

    [Fact]
    public void ToAnalysisResult_WithAgentFindings_MergesCorrectly()
    {
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[]
            {
                new Finding
                {
                    Category = "Firewall",
                    Severity = Severity.High,
                    SourceHost = "localhost",
                    Target = "INPUT",
                    ShortDescription = "Default policy is ACCEPT",
                    Details = "Change to DROP"
                }
            },
            Warnings = new[] { "Scanner warning" },
            Summary = "Audit complete"
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Single(analysisResult.Findings);
        Assert.Single(analysisResult.Warnings);
        Assert.Equal("Firewall", analysisResult.Findings[0].Category);
    }

    [Fact]
    public void ToAnalysisResult_WithLogAnalysis_MergesBothSources()
    {
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[]
            {
                new Finding
                {
                    Category = "Port",
                    Severity = Severity.Medium,
                    SourceHost = "localhost",
                    Target = "0.0.0.0:3306",
                    ShortDescription = "Database exposed",
                    Details = "Bind to 127.0.0.1"
                }
            },
            LogAnalysisResult = new AnalysisResult
            {
                TotalLines = 100,
                ParsedLines = 95,
                Findings = new[]
                {
                    new Finding
                    {
                        Category = FindingCategories.PortScan,
                        Severity = Severity.Critical,
                        SourceHost = "10.0.0.5",
                        Target = "192.168.1.10",
                        ShortDescription = "Port scan detected",
                        Details = "Scanned 50 ports"
                    }
                },
                Warnings = new[] { "Log warning" }
            },
            Warnings = new[] { "Agent warning" }
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Equal(2, analysisResult.Findings.Count);
        Assert.Equal(2, analysisResult.Warnings.Count); // agent + log
        Assert.Equal(100, analysisResult.TotalLines);
        Assert.Equal(95, analysisResult.ParsedLines);
    }

    [Fact]
    public void ToAnalysisResult_NoFindings_ReturnsEmpty()
    {
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Empty(analysisResult.Findings);
        Assert.Empty(analysisResult.Warnings);
    }

    [Fact]
    public void ToAnalysisResult_RuleId_IsPreserved()
    {
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[]
            {
                new Finding
                {
                    Category = "Firewall",
                    Severity = Severity.High,
                    SourceHost = "localhost",
                    Target = "INPUT",
                    ShortDescription = "Default policy is ACCEPT",
                    Details = "Change to DROP",
                    RuleId = "FW-001"
                }
            }
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Single(analysisResult.Findings);
        Assert.Equal("FW-001", analysisResult.Findings[0].RuleId);
    }

    [Fact]
    public void ToAnalysisResult_DeduplicatesById()
    {
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "test",
            ShortDescription = "Duplicate",
            Details = "Same finding twice"
        };

        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = new[] { finding, finding },
            LogAnalysisResult = new AnalysisResult
            {
                Findings = new[] { finding }
            }
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Single(analysisResult.Findings);
    }

    [Fact]
    public void ToAnalysisResult_WithSuppressionStore_IncludesActiveSuppressions()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "INPUT",
            Reason = "Lab environment",
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        });

        var generator = new AgentReportGenerator(store);
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>(),
            SuppressedCount = 1
        };

        var analysisResult = generator.ToAnalysisResult(agentResult);

        Assert.Equal(1, analysisResult.SuppressedCount);
        Assert.Single(analysisResult.ActiveSuppressions);
        Assert.Equal("FW-001", analysisResult.ActiveSuppressions[0].RuleId);
        Assert.Equal("INPUT", analysisResult.ActiveSuppressions[0].Target);
    }

    [Fact]
    public void ToAnalysisResult_WithSuppressionStore_ExpiredSuppressionsExcluded()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "INPUT",
            ExpiresAt = DateTime.UtcNow.AddMinutes(-1)
        });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "OUTPUT" });

        var generator = new AgentReportGenerator(store);
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>()
        };

        var analysisResult = generator.ToAnalysisResult(agentResult);

        Assert.Single(analysisResult.ActiveSuppressions);
        Assert.Equal("FW-002", analysisResult.ActiveSuppressions[0].RuleId);
    }

    [Fact]
    public void ToAnalysisResult_WithRiskScorecard_PreservesScorecard()
    {
        var scorecard = new RiskScorecard
        {
            NumericScore = 72.5,
            LetterGrade = "C",
            SummaryStatus = "Elevated",
            TotalFindings = 3,
            ByCategory = new[]
            {
                new CategoryRisk { Category = "Port", FindingCount = 2, TotalDeduction = 15.0, AverageSeverity = 3.0 },
                new CategoryRisk { Category = "Firewall", FindingCount = 1, TotalDeduction = 12.5, AverageSeverity = 2.5 }
            }
        };

        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>(),
            RiskScorecard = scorecard
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.NotNull(analysisResult.RiskScorecard);
        Assert.Equal(72.5, analysisResult.RiskScorecard.NumericScore);
        Assert.Equal("C", analysisResult.RiskScorecard.LetterGrade);
        Assert.Equal("Elevated", analysisResult.RiskScorecard.SummaryStatus);
        Assert.Equal(3, analysisResult.RiskScorecard.TotalFindings);
        Assert.Equal(2, analysisResult.RiskScorecard.ByCategory.Count);
        Assert.Equal("Port", analysisResult.RiskScorecard.ByCategory[0].Category);
    }

    [Fact]
    public void ToAnalysisResult_WithoutRiskScorecard_SetsNull()
    {
        var agentResult = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            AgentFindings = Array.Empty<Finding>()
        };

        var analysisResult = _generator.ToAnalysisResult(agentResult);

        Assert.Null(analysisResult.RiskScorecard);
    }
}
