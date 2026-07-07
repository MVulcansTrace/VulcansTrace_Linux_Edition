using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SudoersScannerTests
{
    [Fact]
    public void ParsePrivilegeLine_FullSudoNoPasswd_ReturnsEntry()
    {
        var line = "admin ALL=(ALL:ALL) NOPASSWD: ALL";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.NotNull(entry);
        Assert.Equal("admin", entry!.Principal);
        Assert.False(entry.IsGroup);
        Assert.Equal("ALL", entry.Hosts);
        Assert.Equal("(ALL:ALL)", entry.RunAs);
        Assert.Equal("ALL", entry.Commands);
        Assert.True(entry.NoPasswd);
        Assert.True(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void ParsePrivilegeLine_GroupFullSudo_ReturnsGroupEntry()
    {
        var line = "%wheel ALL=(ALL) ALL";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.NotNull(entry);
        Assert.Equal("%wheel", entry!.Principal);
        Assert.True(entry.IsGroup);
        Assert.Equal("ALL", entry.Hosts);
        Assert.Equal("(ALL)", entry.RunAs);
        Assert.Equal("ALL", entry.Commands);
        Assert.False(entry.NoPasswd);
        Assert.True(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void ParsePrivilegeLine_RestrictedCommand_ReturnsEntryButNotFullSudo()
    {
        var line = "backup localhost=/bin/systemctl restart nginx";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers.d/backup", line);

        Assert.NotNull(entry);
        Assert.Equal("backup", entry!.Principal);
        Assert.False(entry.IsGroup);
        Assert.Equal("localhost", entry.Hosts);
        Assert.Equal("", entry.RunAs);
        Assert.Equal("/bin/systemctl restart nginx", entry.Commands);
        Assert.False(entry.NoPasswd);
        Assert.False(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void ParsePrivilegeLine_DefaultsLine_ReturnsNull()
    {
        var line = "Defaults env_reset";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.Null(entry);
    }

    [Fact]
    public void ParsePrivilegeLine_CommentLine_ReturnsNull()
    {
        var line = "# admin ALL=(ALL) ALL";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.Null(entry);
    }

    [Fact]
    public void ParsePrivilegeLine_IncludeDirective_ReturnsNull()
    {
        var line = "@includedir /etc/sudoers.d";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.Null(entry);
    }

    [Fact]
    public void ParsePrivilegeLine_InlineComment_StripsComment()
    {
        var line = "admin ALL=(ALL:ALL) ALL # admin can do anything";

        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.NotNull(entry);
        Assert.Equal("admin", entry!.Principal);
        Assert.Equal("ALL", entry.Commands);
    }

    [Theory]
    [InlineData("admin ALL=(ALL:ALL) NOEXEC: NOPASSWD: ALL")]
    [InlineData("admin ALL=(ALL:ALL) NOPASSWD: NOEXEC: ALL")]
    public void ParsePrivilegeLine_NoPasswdNotFirstTag_Detected(string line)
    {
        // NOPASSWD may appear anywhere in the leading tag sequence; it must be detected.
        var entry = SudoersScanner.ParsePrivilegeLine("/etc/sudoers", line);

        Assert.NotNull(entry);
        Assert.True(entry!.NoPasswd, "NOPASSWD tag must be detected regardless of position.");
        Assert.Equal("ALL", entry.Commands);
        Assert.True(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void IsFullSudoEntry_RestrictedHost_ReturnsFalse()
    {
        var entry = new SudoersEntry
        {
            Principal = "admin",
            Hosts = "localhost",
            RunAs = "(ALL:ALL)",
            Commands = "ALL"
        };

        Assert.False(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void IsFullSudoEntry_RestrictedCommand_ReturnsFalse()
    {
        var entry = new SudoersEntry
        {
            Principal = "admin",
            Hosts = "ALL",
            RunAs = "(ALL:ALL)",
            Commands = "/bin/ls"
        };

        Assert.False(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Theory]
    [InlineData("/usr/bin/wall")]
    [InlineData("/usr/bin/install")]
    [InlineData("/opt/tools/ALLOWLIST")]
    public void IsFullSudoEntry_CommandContainingAllSubstring_ReturnsFalse(string command)
    {
        var entry = new SudoersEntry
        {
            Principal = "admin",
            Hosts = "ALL",
            RunAs = "(ALL:ALL)",
            Commands = command
        };

        Assert.False(SudoersScanner.IsFullSudoEntry(entry));
    }

    [Fact]
    public void IsFullSudoEntry_CommaSeparatedAllCommand_ReturnsTrue()
    {
        var entry = new SudoersEntry
        {
            Principal = "admin",
            Hosts = "ALL",
            RunAs = "(ALL:ALL)",
            Commands = "/bin/ls, ALL"
        };

        Assert.True(SudoersScanner.IsFullSudoEntry(entry));
    }
}
