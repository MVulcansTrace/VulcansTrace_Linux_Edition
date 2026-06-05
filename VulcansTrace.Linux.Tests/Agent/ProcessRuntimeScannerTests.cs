using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ProcessRuntimeScannerTests
{
    [Fact]
    public void ParseMapLine_ValidLine_ReturnsMap()
    {
        var line = "00400000-0040c000 r-xp 00000000 08:01 1310734 /bin/cat";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.NotNull(map);
        Assert.Equal("00400000-0040c000", map!.AddressRange);
        Assert.Equal("r-xp", map.Permissions);
        Assert.Equal("/bin/cat", map.Path);
    }

    [Fact]
    public void ParseMapLine_HeapEntry_ReturnsMap()
    {
        var line = "55a3b2c1d000-55a3b2c3e000 rw-p 00000000 00:00 0 [heap]";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.NotNull(map);
        Assert.Equal("[heap]", map!.Path);
        Assert.Equal("rw-p", map.Permissions);
    }

    [Fact]
    public void ParseMapLine_RwxEntry_ReturnsMapWithRwx()
    {
        var line = "7f8a1b2c3000-7f8a1b2c4000 rwxp 00000000 00:00 0";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.NotNull(map);
        Assert.Equal("rwxp", map!.Permissions);
    }

    [Fact]
    public void ParseMapLine_PathWithSpaces_ReturnsFullPath()
    {
        var line = "7f8a1b2c3000-7f8a1b2c4000 r--p 00000000 08:01 1234567 /usr/share/my application/data.bin";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.NotNull(map);
        Assert.Equal("/usr/share/my application/data.bin", map!.Path);
    }

    [Fact]
    public void ParseMapLine_TooFewParts_ReturnsNull()
    {
        var line = "00400000-0040c000 r-xp";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.Null(map);
    }

    [Fact]
    public void ParseMapLine_EmptyString_ReturnsNull()
    {
        var map = ProcessRuntimeScanner.ParseMapLine(string.Empty);
        Assert.Null(map);
    }

    [Fact]
    public void ParseMapLine_InvalidPermissions_ReturnsNull()
    {
        var line = "00400000-0040c000 rwx! 00000000 08:01 1310734 /bin/cat";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.Null(map);
    }

    [Fact]
    public void ParseMapLine_WrongPermissionLength_ReturnsNull()
    {
        var line = "00400000-0040c000 rwx 00000000 08:01 1310734 /bin/cat";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.Null(map);
    }

    [Fact]
    public void ParseMapLine_NoPath_ReturnsEmptyPath()
    {
        var line = "7f8a1b2c3000-7f8a1b2c4000 rw-p 00000000 00:00 0";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.NotNull(map);
        Assert.Equal(string.Empty, map!.Path);
    }

    [Fact]
    public void ParseMapLine_InvalidAddressRange_ReturnsNull()
    {
        var line = "nothex-rwxp 00000000 08:01 1310734 /bin/cat";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.Null(map);
    }

    [Fact]
    public void ParseMapLine_MissingDashInAddress_ReturnsNull()
    {
        var line = "00400000 0040c000 r-xp 00000000 08:01 1310734 /bin/cat";

        var map = ProcessRuntimeScanner.ParseMapLine(line);

        Assert.Null(map);
    }

    [Theory]
    [InlineData("apache2", "bash", true)]
    [InlineData("nginx", "python3", true)]
    [InlineData("httpd", "perl", true)]
    [InlineData("sshd", "python", true)]
    [InlineData("sshd", "bash", false)]
    [InlineData("mysqld", "sh", true)]
    [InlineData("postgres", "ruby", true)]
    [InlineData("mongod", "python", true)]
    [InlineData("cron", "curl", true)]
    [InlineData("crond", "wget", true)]
    [InlineData("apache2", "php-fpm", false)]
    [InlineData("nginx", "nginx", false)]
    [InlineData("systemd", "bash", false)]
    [InlineData("nginx", "python3.11", true)]
    [InlineData("sshd", "php8.1", true)]
    [InlineData("mysqld", "ruby3.2", true)]
    [InlineData("apache2", "perl5.34", true)]
    public void IsSuspiciousPair_VariousPairs_ReturnsExpected(string parent, string child, bool expected)
    {
        var result = SuspiciousParentChildRule.IsSuspiciousPair(parent, child);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("xk9j2m4p7q", true)]   // random, 10 chars, 3 digits
    [InlineData("abc123def456", true)] // 12 chars, 6 digits
    [InlineData("systemd", false)]     // too short
    [InlineData("systemd-networkd", false)] // contains hyphen, fails alphanumeric
    [InlineData("a1", false)]          // too short
    [InlineData("abcdefghij", false)]  // no digits
    [InlineData("abc12", false)]       // too short
    [InlineData("1234567890", true)]   // 10 chars, 10 digits
    public void IsAnomalousName_VariousNames_ReturnsExpected(string name, bool expected)
    {
        var result = OrphanedAnomalousProcessRule.IsAnomalousName(name);
        Assert.Equal(expected, result);
    }
}
