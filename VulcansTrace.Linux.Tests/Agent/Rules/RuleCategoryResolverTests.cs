using VulcansTrace.Linux.Agent.Rules;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Rules;

public class RuleCategoryResolverTests
{
    [Theory]
    [InlineData("FW-002", "FW")]
    [InlineData("fw-002", "FW")]
    [InlineData("SSH-001", "SSH")]
    [InlineData("USER-003", "USER")]
    [InlineData("KERN-005", "KERN")]
    [InlineData("UNKNOWN", "UNKNOWN")]
    public void ResolvePrefix_ReturnsUppercasePrefix(string ruleId, string expected)
    {
        Assert.Equal(expected, RuleCategoryResolver.ResolvePrefix(ruleId));
    }

    [Fact]
    public void ResolvePrefix_EmptyRuleId_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, RuleCategoryResolver.ResolvePrefix(""));
        Assert.Equal(string.Empty, RuleCategoryResolver.ResolvePrefix("   "));
    }

    [Theory]
    [InlineData("SSH-002", "config-management")]
    [InlineData("FW-001", "firewall")]
    [InlineData("USER-001", "Privileged account")]
    [InlineData("KERN-003", "sysctl")]
    [InlineData("PORT-001", "automated process")]
    public void GetGuidance_ReturnsCategorySpecificText(string ruleId, string expectedSnippet)
    {
        var guidance = RuleCategoryResolver.GetGuidance(ruleId);
        Assert.Contains(expectedSnippet, guidance, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SSH-002", "SSH configuration")]
    [InlineData("FW-001", "firewall startup")]
    [InlineData("USER-001", "identity-management")]
    [InlineData("KERN-003", "sysctl")]
    [InlineData("PORT-001", "automation")]
    public void GetRegressionGuidance_ReturnsConciseCategorySpecificText(string ruleId, string expectedSnippet)
    {
        var guidance = RuleCategoryResolver.GetRegressionGuidance(ruleId);
        Assert.Contains(expectedSnippet, guidance, StringComparison.OrdinalIgnoreCase);
    }
}
