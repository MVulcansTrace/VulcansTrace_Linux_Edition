using System;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Reports;

public class IntentSummaryBuilderTests
{
    private readonly IntentSummaryBuilder _builder = new();

    [Fact]
    public void BuildMissingToolLead_OnlyMissingTool_PrependsFriendlyMessage()
    {
        var warning = new UserFriendlyWarning(WarningCategory.MissingTool, "iptables is missing.", 1);

        var lead = _builder.BuildMissingToolLead(AgentIntent.FirewallCheck, Array.Empty<Finding>(), 0, warning);

        Assert.Equal("I ran a firewall check. iptables is missing.", lead);
    }

    [Fact]
    public void BuildMissingToolLead_WithFindings_SummarizesIssuesAndPassed()
    {
        var warning = new UserFriendlyWarning(WarningCategory.MissingTool, "nftables is missing.", 1);
        var findings = new[] { new Finding { Severity = Severity.Critical } };

        var lead = _builder.BuildMissingToolLead(AgentIntent.FirewallCheck, findings, 2, warning);

        Assert.StartsWith("I ran a firewall check. nftables is missing.", lead);
        Assert.Contains("1 issue", lead);
        Assert.Contains("1 High/Critical", lead);
        Assert.Contains("2 other checks passed", lead);
    }

    [Fact]
    public void BuildMissingToolLead_NoFindingsWithPassed_IncludesPassedCount()
    {
        var warning = new UserFriendlyWarning(WarningCategory.MissingTool, "iptables is missing.", 1);

        var lead = _builder.BuildMissingToolLead(AgentIntent.FirewallCheck, Array.Empty<Finding>(), 3, warning);

        Assert.Contains("3 other checks passed", lead);
        Assert.DoesNotContain("issue", lead);
    }

    [Fact]
    public void BuildMissingToolLead_FindingsButNoPassed_OmitsPassedClause()
    {
        var warning = new UserFriendlyWarning(WarningCategory.MissingTool, "iptables is missing.", 1);
        var findings = new[] { new Finding { Severity = Severity.High } };

        var lead = _builder.BuildMissingToolLead(AgentIntent.FirewallCheck, findings, 0, warning);

        Assert.Contains("1 issue", lead);
        Assert.DoesNotContain("0 check", lead);
        Assert.DoesNotContain("passed", lead);
    }
}
