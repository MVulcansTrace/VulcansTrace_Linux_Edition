using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationPlanBuilderTests
{
    [Fact]
    public void Build_Empty_Findings_Returns_Empty_Plan()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var plan = builder.Build(Array.Empty<Finding>());

        Assert.Empty(plan.Sections);
    }

    [Fact]
    public void Build_Extracts_Commands_From_SuggestedNextAction()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-001",
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "Default policy is ACCEPT",
            Target = "INPUT",
            Details = @"**Suggested next action:**
1. Change policy: `sudo iptables -P INPUT DROP`
2. Save rules: `sudo iptables-save > /etc/iptables/rules.v4`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Equal(2, plan.Sections[0].RemediationCommands.Count);
        Assert.Contains("sudo iptables -P INPUT DROP", plan.Sections[0].RemediationCommands.Select(c => c.Command));
    }

    [Fact]
    public void Build_Extracts_Verification_Commands()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-002",
            Category = "Firewall",
            Severity = Severity.Medium,
            ShortDescription = "SSH exposed",
            Target = "SSH/22",
            Details = @"**How to verify:**
1. Check: `sudo ss -tulnp | grep :22`"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.Single(plan.Sections[0].VerificationCommands);
        Assert.Contains("sudo ss -tulnp | grep :22", plan.Sections[0].VerificationCommands.Select(c => c.Command));
    }

    [Fact]
    public void Build_Generates_Generic_Rollback_When_None_In_Template()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "FW-004",
            Category = "Firewall",
            Severity = Severity.Critical,
            ShortDescription = "No firewall",
            Target = "firewall",
            Details = "No rollback hints in template."
        };

        var plan = builder.Build(new[] { finding });

        Assert.Single(plan.Sections);
        Assert.True(plan.Sections[0].RollbackHints.Count > 0);
    }

    [Fact]
    public void Build_Extracts_Rollback_Hints_From_Template()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = "TEST-001",
            Category = "Port",
            Severity = Severity.Medium,
            ShortDescription = "Test",
            Target = "test",
            Details = @"**Suggested next action:**
`do something`

**Rollback hints:**
- Undo the thing
- Restore backup"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Equal(2, plan.Sections[0].RollbackHints.Count);
        Assert.Contains("Undo the thing", plan.Sections[0].RollbackHints);
    }

    [Fact]
    public void Build_Skips_Findings_Without_RuleId()
    {
        var builder = new RemediationPlanBuilder(new ExplanationProvider());
        var finding = new Finding
        {
            RuleId = null,
            Category = "Firewall",
            Severity = Severity.High,
            ShortDescription = "No rule id"
        };

        var plan = builder.Build(new[] { finding });

        Assert.Empty(plan.Sections);
    }
}
