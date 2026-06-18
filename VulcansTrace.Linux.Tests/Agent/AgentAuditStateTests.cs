using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class AgentAuditStateTests
{
    [Fact]
    public void RememberAudit_StoresLastResultIntentAndFindings()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("TEST-001", "target");
        var result = new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            AgentFindings = new[] { finding }
        };

        state.RememberAudit(result, AgentIntent.FirewallCheck, new[] { ("TEST-001", finding) });

        Assert.Same(result, state.LastResult);
        Assert.Equal(AgentIntent.FirewallCheck, state.LastAuditIntent);
        Assert.Same(finding, state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public void FindPreviousFinding_MatchesReferenceFields()
    {
        var state = new AgentAuditState();
        var finding = CreateFinding("TEST-001", "ssh-target") with
        {
            Category = "SSH",
            ShortDescription = "Open SSH service",
            Details = "Details mention hardened configuration"
        };

        state.RememberAudit(
            new AgentResult { Intent = AgentIntent.FullAudit, AgentFindings = new[] { finding } },
            AgentIntent.FullAudit,
            new[] { ("TEST-001", finding) });

        Assert.Same(finding, state.FindPreviousFinding("open ssh"));
        Assert.Same(finding, state.FindPreviousFinding("ssh"));
        Assert.Same(finding, state.FindPreviousFinding("hardened"));
        Assert.Same(finding, state.FindPreviousFinding("ssh-target"));
    }

    private static Finding CreateFinding(string ruleId, string target)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = "Test finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }
}
