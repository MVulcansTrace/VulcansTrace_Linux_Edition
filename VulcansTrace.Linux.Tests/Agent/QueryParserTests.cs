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
    [InlineData("help", AgentIntent.Help)]
    [InlineData("what can you do", AgentIntent.Help)]
    [InlineData("capabilities", AgentIntent.Help)]
    public void Parse_VariousQueries_ReturnsExpectedIntent(string query, AgentIntent expected)
    {
        var result = _parser.Parse(query);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void Parse_UnknownQuery_ReturnsHelp()
    {
        var result = _parser.Parse("tell me a joke");
        Assert.Equal(AgentIntent.Help, result);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsHelp()
    {
        var result = _parser.Parse("");
        Assert.Equal(AgentIntent.Help, result);
    }

    [Fact]
    public void Parse_Whitespace_ReturnsHelp()
    {
        var result = _parser.Parse("   ");
        Assert.Equal(AgentIntent.Help, result);
    }

    [Fact]
    public void Parse_CaseInsensitive_MatchesCorrectly()
    {
        var result = _parser.Parse("CHECK MY FIREWALL");
        Assert.Equal(AgentIntent.FirewallCheck, result);
    }
}
