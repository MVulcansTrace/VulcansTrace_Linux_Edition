using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentResultFinalizerTests
{
    [Fact]
    public void FinalizeAudit_BuildsResultWithScorecardsAndUpdatesState()
    {
        var auditState = new AgentAuditState();
        var complianceScorecard = new ComplianceScorecard { OverallScore = 95, SummaryStatus = "Pass" };
        var riskScorecard = new RiskScorecard { NumericScore = 80, LetterGrade = "B", SummaryStatus = "Moderate" };
        var complianceBuilder = new TestComplianceScorecardBuilder(complianceScorecard);
        var riskBuilder = new TestRiskScorecardBuilder(riskScorecard);
        var finalizer = new AgentResultFinalizer(auditState, historyStore: null, complianceBuilder, riskBuilder);
        var finding = CreateFinding();
        var ruleResult = RuleResult.Fail("TEST-001", "Test", "TEST-001", "Test failed", Severity.High, "target");

        var result = finalizer.FinalizeAudit(new AgentResultFinalizationRequest(
            AgentIntent.FullAudit,
            new[] { finding },
            LogAnalysisResult: null,
            new[] { "warning" },
            "summary",
            new[] { ruleResult },
            PassedCount: 0,
            FailedCount: 1,
            SuppressedCount: 0,
            CrashedCount: 0,
            "capability report",
            new[] { ("TEST-001", finding) }));

        Assert.Equal(AgentIntent.FullAudit, result.Intent);
        Assert.Equal("summary", result.Summary);
        Assert.Same(finding, result.AgentFindings[0]);
        Assert.Same(ruleResult, result.RuleResults[0]);
        Assert.Equal("warning", result.Warnings[0]);
        Assert.Equal("capability report", result.CapabilityReport);
        Assert.Same(complianceScorecard, result.Scorecard);
        Assert.Same(riskScorecard, result.RiskScorecard);
        Assert.Same(result, auditState.LastResult);
        Assert.Equal(AgentIntent.FullAudit, auditState.LastAuditIntent);
        Assert.Same(finding, auditState.FindPreviousFinding("TEST-001"));
        Assert.Same(ruleResult, complianceBuilder.ObservedRuleResults?[0]);
        Assert.Same(finding, riskBuilder.ObservedFindings?[0]);
    }

    private static Finding CreateFinding()
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = "TEST-001",
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = "Test finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private sealed class TestComplianceScorecardBuilder(ComplianceScorecard scorecard) : IComplianceScorecardBuilder
    {
        public IReadOnlyList<RuleResult>? ObservedRuleResults { get; private set; }

        public ComplianceScorecard? Build(
            IReadOnlyList<RuleResult> ruleResults,
            IAuditHistoryStore? historyStore = null,
            DateTime? timestamp = null)
        {
            ObservedRuleResults = ruleResults;
            return scorecard;
        }
    }

    private sealed class TestRiskScorecardBuilder(RiskScorecard scorecard) : IRiskScorecardBuilder
    {
        public IReadOnlyList<Finding>? ObservedFindings { get; private set; }

        public RiskScorecard? Build(IReadOnlyList<Finding> findings, DateTime? timestamp = null)
        {
            ObservedFindings = findings;
            return scorecard;
        }
    }
}
