using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class CategoryDisplayTests
{
    [Theory]
    [InlineData("FilesystemAudit", "Filesystem Audit")]
    [InlineData("ProcessRuntime", "Process Runtime")]
    [InlineData("PackageVulnerability", "Package Vulnerability")]
    [InlineData("FilePermission", "File Permission")]
    [InlineData("UserAccount", "User Account")]
    [InlineData("ThreatIntel", "Threat Intel")]
    [InlineData("CronJob", "Cron Job")]
    [InlineData("PrivilegeEscalation", "Privilege Escalation")]
    [InlineData("LateralMovement", "Lateral Movement")]
    [InlineData("C2Channel", "C2 Channel")]
    [InlineData("MacSpoofing", "Mac Spoofing")]
    [InlineData("InterfaceHopping", "Interface Hopping")]
    [InlineData("UnusualPacketSize", "Unusual Packet Size")]
    public void ToDisplayName_PascalCase_SplitsIntoWords(string input, string expected)
    {
        Assert.Equal(expected, CategoryDisplay.ToDisplayName(input));
    }

    [Theory]
    [InlineData("SSH", "SSH")]
    [InlineData("ssh", "SSH")]
    [InlineData("Mac", "MAC")]
    [InlineData("Yara", "YARA")]
    [InlineData("yara", "YARA")]
    public void ToDisplayName_Acronyms_UseOverrides(string input, string expected)
    {
        Assert.Equal(expected, CategoryDisplay.ToDisplayName(input));
    }

    [Theory]
    [InlineData("Firewall", "Firewall")]
    [InlineData("Service", "Service")]
    [InlineData("Port", "Port")]
    [InlineData("Kernel", "Kernel")]
    [InlineData("Logging", "Logging")]
    [InlineData("Sudoers", "Sudoers")]
    [InlineData("Systemd", "Systemd")]
    [InlineData("Bootloader", "Bootloader")]
    [InlineData("Network", "Network")]
    [InlineData("Container", "Container")]
    [InlineData("Kubernetes", "Kubernetes")]
    [InlineData("Beaconing", "Beaconing")]
    [InlineData("Novelty", "Novelty")]
    public void ToDisplayName_SingleWord_Unchanged(string input, string expected)
    {
        Assert.Equal(expected, CategoryDisplay.ToDisplayName(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ToDisplayName_NullOrWhitespace_ReturnsEmpty(string? input)
    {
        Assert.Equal(string.Empty, CategoryDisplay.ToDisplayName(input));
    }
}
