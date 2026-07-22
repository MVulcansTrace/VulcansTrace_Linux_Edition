using VulcansTrace.Linux.Core.Parsing;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class LogSnippetDetectorTests
{
    private const string SyslogLine = "Jan 19 10:15:32 server sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2";
    private const string FirewallLine = "kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
    private const string IsoLine = "2026-01-19T10:15:34.123456+00:00 nf_tables: INPUT IN=eth0 SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP";

    [Fact]
    public void HasLogIntent_ThreeSyslogLines_ReturnsTrue()
    {
        var text = string.Join('\n', SyslogLine, SyslogLine, SyslogLine);

        Assert.True(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_ExactlyTwoLogLines_ReturnsFalse()
    {
        var text = string.Join('\n', SyslogLine, SyslogLine);

        Assert.False(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_ChatSentence_ReturnsFalse()
    {
        Assert.False(LogSnippetDetector.HasLogIntent("Why is port 443 flagged as suspicious?"));
    }

    [Fact]
    public void HasLogIntent_MixedTwoLogLinesPlusProse_ReturnsFalse()
    {
        // A pasted question quoting a couple of log lines is still a chat
        // message — the threshold is a line count, not a ratio.
        var text = string.Join('\n', "what do these mean?", SyslogLine, FirewallLine);

        Assert.False(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_IsoTimestampLines_ReturnsTrue()
    {
        var text = string.Join('\n', IsoLine, IsoLine, IsoLine);

        Assert.True(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_FirewallKeyValueLines_ReturnsTrue()
    {
        var text = string.Join('\n', FirewallLine, FirewallLine, FirewallLine);

        Assert.True(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_MixedLogFormats_CrossesThreshold()
    {
        var text = string.Join('\n', SyslogLine, IsoLine, FirewallLine);

        Assert.True(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_BlankLinesBetweenLogs_StillCounts()
    {
        var text = string.Join('\n', SyslogLine, "", "   ", SyslogLine, SyslogLine);

        Assert.True(LogSnippetDetector.HasLogIntent(text));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \n  \n")]
    public void HasLogIntent_EmptyOrWhitespace_ReturnsFalse(string? text)
    {
        Assert.False(LogSnippetDetector.HasLogIntent(text));
    }

    [Fact]
    public void HasLogIntent_SlashCommand_ReturnsFalse()
    {
        Assert.False(LogSnippetDetector.HasLogIntent("/audit full"));
    }
}
