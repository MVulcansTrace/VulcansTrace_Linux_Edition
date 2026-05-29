using VulcansTrace.Linux.Agent.Explanations;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class VerificationCommandExtractorTests
{
    [Fact]
    public void Extract_Empty_Returns_Empty()
    {
        var result = VerificationCommandExtractor.Extract("");
        Assert.Empty(result);
    }

    [Fact]
    public void Extract_Null_Returns_Empty()
    {
        var result = VerificationCommandExtractor.Extract(null!);
        Assert.Empty(result);
    }

    [Fact]
    public void Extract_NumberedList_With_Backticks_Returns_Commands()
    {
        var markdown = @"**How to verify:**
1. Check the current policy: `sudo iptables -L INPUT | head -n 1`
2. Look for the line: `grep 'policy DROP' /tmp/rules.txt`
3. Test: `ping -c 1 8.8.8.8`";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Equal(3, result.Count);
        Assert.Equal("sudo iptables -L INPUT | head -n 1", result[0].FullCommand);
        Assert.Equal("grep 'policy DROP' /tmp/rules.txt", result[1].FullCommand);
        Assert.Equal("ping -c 1 8.8.8.8", result[2].FullCommand);
    }

    [Fact]
    public void Extract_Fallback_To_All_Backticks_When_No_Numbered_List()
    {
        var markdown = @"**How to verify:**
Run `sudo ss -tulnp | grep :22` and then `sudo iptables -L INPUT -n | grep 22`";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Equal(2, result.Count);
        Assert.Equal("sudo ss -tulnp | grep :22", result[0].FullCommand);
        Assert.Equal("sudo iptables -L INPUT -n | grep 22", result[1].FullCommand);
    }

    [Fact]
    public void Extract_Fallback_Classifies_CommandSafety()
    {
        var markdown = @"**How to verify:**
Run `sudo ss -tulnp | grep :22` before changing anything.";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Single(result);
        Assert.Equal(CommandSafety.ReadOnly, result[0].Safety);
    }

    [Fact]
    public void Extract_Deduplicates_Commands()
    {
        var markdown = @"Run `sudo ss -tulnp` and then `sudo ss -tulnp` again.";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Single(result);
        Assert.Equal("sudo ss -tulnp", result[0].FullCommand);
    }

    [Fact]
    public void Extract_NumberedList_Takes_Precedence_Over_Fallback()
    {
        var markdown = @"**How to verify:**
1. First: `command-one`
2. Second: `command-two`

Also see `other-stuff` for more info.";

        var result = VerificationCommandExtractor.Extract(markdown);

        // When numbered list items with backticks are found, only those are extracted
        Assert.Equal(2, result.Count);
        Assert.Equal("command-one", result[0].FullCommand);
        Assert.Equal("command-two", result[1].FullCommand);
    }

    [Fact]
    public void Extract_NumberedList_Without_Backticks_Is_Empty()
    {
        var markdown = @"**How to verify:**
1. Check the current policy
2. Look for the line";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Empty(result);
    }

    [Fact]
    public void Extract_Preserves_Order()
    {
        var markdown = @"1. `first-command`
2. `second-command`
3. `third-command`";

        var result = VerificationCommandExtractor.Extract(markdown);

        Assert.Equal(3, result.Count);
        Assert.Equal("first-command", result[0].FullCommand);
        Assert.Equal("second-command", result[1].FullCommand);
        Assert.Equal("third-command", result[2].FullCommand);
    }

    [Fact]
    public void ExtractHowToVerify_Excludes_SuggestedNextAction_Commands()
    {
        var markdown = @"**How to verify:**
1. Check current state: `sudo iptables -L INPUT`

**Suggested next action:**
1. Consider changing policy: `sudo iptables -P INPUT DROP`";

        var result = VerificationCommandExtractor.ExtractHowToVerify(markdown);

        Assert.Single(result);
        Assert.Equal("sudo iptables -L INPUT", result[0].FullCommand);
    }
}
