using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class RootCauseMatcherTests
{
    private readonly RootCauseMatcher _matcher = new();

    [Theory]
    [InlineData("We use Ansible")]
    [InlineData("puppet applies it")]
    [InlineData("chef cookbook")]
    [InlineData("saltstack state")]
    [InlineData("cloud-init user-data")]
    public void Match_ConfigManagementAnswer_ReturnsConfigManagementRootCause(string answer)
    {
        var match = _matcher.Match(answer, "FW-004");

        Assert.Equal(RootCauseCategory.ConfigManagement, match.Category);
        Assert.Contains("config-management tool", match.Explanation);
        Assert.Contains("FW-004", match.SourceIds);
    }

    [Theory]
    [InlineData("It came back after a reboot")]
    [InlineData("I restarted the service")]
    [InlineData("After the system update")]
    [InlineData("I ran apt upgrade")]
    public void Match_RebootUpdateAnswer_ReturnsNonPersistentRootCause(string answer)
    {
        var match = _matcher.Match(answer, "FW-004");

        Assert.Equal(RootCauseCategory.NonPersistent, match.Category);
        Assert.Contains("doesn't persist", match.Explanation);
    }

    [Theory]
    [InlineData("I don't know")]
    [InlineData("not sure")]
    [InlineData("unsure")]
    [InlineData("no idea")]
    public void Match_UncertainAnswer_ReturnsFallbackGuidance(string answer)
    {
        var match = _matcher.Match(answer, "FW-004");

        Assert.Equal(RootCauseCategory.Uncertain, match.Category);
        Assert.Contains("firewall keeps reverting", match.Explanation);
    }

    [Fact]
    public void Match_DefaultAnswer_ReturnsUnknownCategoryWithGuidance()
    {
        var match = _matcher.Match("something else happened", "FW-004");

        Assert.Equal(RootCauseCategory.Unknown, match.Category);
        Assert.Contains("couldn't match", match.Explanation);
    }

    [Fact]
    public void Match_UncertainAnswer_UsesRuleSpecificGuidance()
    {
        var match = _matcher.Match("I don't know", "SSH-001");

        Assert.Contains("SSH setting", match.Explanation);
    }

    [Fact]
    public void Match_EmptyAnswer_Throws()
    {
        Assert.Throws<ArgumentException>(() => _matcher.Match("", "FW-004"));
    }
}
