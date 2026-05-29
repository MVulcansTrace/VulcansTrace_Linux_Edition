using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
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
}
