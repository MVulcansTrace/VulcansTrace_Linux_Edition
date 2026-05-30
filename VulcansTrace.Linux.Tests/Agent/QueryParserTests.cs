using VulcansTrace.Linux.Agent.Query;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class QueryParserTests
{
    private readonly QueryParser _parser = new();

    [Theory]
    [InlineData("is my system secure?", AgentIntent.FullAudit)]
    [InlineData("run a full check", AgentIntent.FullAudit)]
    [InlineData("health check", AgentIntent.FullAudit)]
    [InlineData("audit everything", AgentIntent.FullAudit)]
    [InlineData("check my firewall", AgentIntent.FirewallCheck)]
    [InlineData("how's my iptables", AgentIntent.FirewallCheck)]
    [InlineData("nftables rules", AgentIntent.FirewallCheck)]
    [InlineData("who am I talking to?", AgentIntent.NetworkCheck)]
    [InlineData("show connections", AgentIntent.NetworkCheck)]
    [InlineData("network traffic", AgentIntent.NetworkCheck)]
    [InlineData("what's running?", AgentIntent.ServiceCheck)]
    [InlineData("check services", AgentIntent.ServiceCheck)]
    [InlineData("systemctl daemons", AgentIntent.ServiceCheck)]
    [InlineData("what ports are open?", AgentIntent.PortCheck)]
    [InlineData("check open ports", AgentIntent.PortCheck)]
    [InlineData("listening ports", AgentIntent.PortCheck)]
    [InlineData("explain this finding", AgentIntent.ExplainFinding)]
    [InlineData("what does this mean", AgentIntent.ExplainFinding)]
    [InlineData("what changed since the last audit", AgentIntent.ShowChanges)]
    [InlineData("difference since last time", AgentIntent.ShowChanges)]
    [InlineData("why is this critical", AgentIntent.ExplainCritical)]
    [InlineData("critical findings", AgentIntent.ExplainCritical)]
    [InlineData("show only firewall issues", AgentIntent.FilterCategory)]
    [InlineData("what should I fix first", AgentIntent.PrioritizeRemediation)]
    [InlineData("remediation plan", AgentIntent.PrioritizeRemediation)]
    [InlineData("which findings are suppressed", AgentIntent.ListSuppressed)]
    [InlineData("suppressed", AgentIntent.ListSuppressed)]
    [InlineData("help", AgentIntent.Help)]
    [InlineData("what can you do", AgentIntent.Help)]
    [InlineData("capabilities", AgentIntent.Help)]
    public void Parse_VariousQueries_ReturnsExpectedIntent(string query, AgentIntent expected)
    {
        var result = _parser.Parse(query);
        Assert.Equal(expected, result.Intent);
    }

    [Fact]
    public void Parse_UnknownQuery_ReturnsHelp()
    {
        var result = _parser.Parse("tell me a joke");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsHelp()
    {
        var result = _parser.Parse("");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Fact]
    public void Parse_Whitespace_ReturnsHelp()
    {
        var result = _parser.Parse("   ");
        Assert.Equal(AgentIntent.Help, result.Intent);
    }

    [Fact]
    public void Parse_CaseInsensitive_MatchesCorrectly()
    {
        var result = _parser.Parse("CHECK MY FIREWALL");
        Assert.Equal(AgentIntent.FirewallCheck, result.Intent);
    }

    [Theory]
    [InlineData("explain FW-001", "FW-001")]
    [InlineData("what does PORT-002 mean", "PORT-002")]
    [InlineData("explain fw-001", "fw-001")]
    [InlineData("explain the ssh rule", "ssh")]
    [InlineData("why is firewall flagged", "firewall")]
    [InlineData("explain finding FW-003", "FW-003")]
    public void Parse_ExplainFinding_WithReference_ReturnsTargetReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Theory]
    [InlineData("explain this finding")]
    [InlineData("what does this mean")]
    [InlineData("why is this flagged")]
    public void Parse_ExplainFinding_WithoutReference_ReturnsNullTargetReference(string query)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("check my firewall")]
    [InlineData("what ports are open?")]
    public void Parse_NonExplainFinding_NeverReturnsTargetReference(string query)
    {
        var result = _parser.Parse(query);
        Assert.Null(result.TargetReference);
    }

    [Theory]
    [InlineData("show only firewall issues", "firewall")]
    [InlineData("filter network findings", "network")]
    [InlineData("only ssh findings", "ssh")]
    public void Parse_FilterCategory_WithReference_ReturnsCategoryReference(string query, string expectedReference)
    {
        var result = _parser.Parse(query);
        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.Equal(expectedReference, result.TargetReference);
    }

    [Fact]
    public void Parse_FilterCategory_WithoutReference_ReturnsNullTargetReference()
    {
        var result = _parser.Parse("show only issues");
        Assert.Equal(AgentIntent.FilterCategory, result.Intent);
        Assert.Null(result.TargetReference);
    }

    [Fact]
    public void Parse_FilterCategory_PortIssues_ReturnsPortCheck()
    {
        // "port" scores higher than filter keywords, so this is treated as a fresh port audit
        var result = _parser.Parse("just show port issues");
        Assert.Equal(AgentIntent.PortCheck, result.Intent);
    }
}
