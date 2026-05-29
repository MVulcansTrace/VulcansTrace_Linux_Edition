using VulcansTrace.Linux.Agent.Explanations;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class CommandSafetyClassifierTests
{
    [Theory]
    [InlineData("cat /etc/passwd", CommandSafety.ReadOnly)]
    [InlineData("ls -la /var/log", CommandSafety.ReadOnly)]
    [InlineData("grep ssh /etc/services", CommandSafety.ReadOnly)]
    [InlineData("ps aux", CommandSafety.ReadOnly)]
    [InlineData("ss -tulnp", CommandSafety.ReadOnly)]
    [InlineData("netstat -tlnp", CommandSafety.ReadOnly)]
    [InlineData("iptables -L INPUT", CommandSafety.ReadOnly)]
    [InlineData("nft list ruleset", CommandSafety.ReadOnly)]
    [InlineData("journalctl --no-pager -u ssh", CommandSafety.ReadOnly)]
    [InlineData("systemctl status sshd", CommandSafety.ReadOnly)]
    [InlineData("ip addr show", CommandSafety.ReadOnly)]
    public void Classify_ReadOnlyCommands_ReturnsReadOnly(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Theory]
    [InlineData("iptables -A INPUT -p tcp --dport 22 -j ACCEPT", CommandSafety.ConfigChange)]
    [InlineData("iptables -P INPUT DROP", CommandSafety.ConfigChange)]
    [InlineData("nft add rule ip filter input tcp dport 22 accept", CommandSafety.ConfigChange)]
    [InlineData("ufw allow 22/tcp", CommandSafety.ConfigChange)]
    [InlineData("sysctl -w net.ipv4.ip_forward=1", CommandSafety.ConfigChange)]
    [InlineData("echo 'AllowUsers admin' >> /etc/ssh/sshd_config", CommandSafety.ConfigChange)]
    public void Classify_ConfigChangeCommands_ReturnsConfigChange(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Theory]
    [InlineData("apt install nginx", CommandSafety.PackageInstall)]
    [InlineData("yum install httpd", CommandSafety.PackageInstall)]
    [InlineData("dnf remove telnet", CommandSafety.PackageInstall)]
    [InlineData("pacman -S openssh", CommandSafety.PackageInstall)]
    [InlineData("pip install requests", CommandSafety.PackageInstall)]
    [InlineData("npm install lodash", CommandSafety.PackageInstall)]
    public void Classify_PackageCommands_ReturnsPackageInstall(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Theory]
    [InlineData("systemctl restart sshd", CommandSafety.ServiceRestart)]
    [InlineData("systemctl start nginx", CommandSafety.ServiceRestart)]
    [InlineData("systemctl stop apache2", CommandSafety.ServiceRestart)]
    [InlineData("systemctl enable docker", CommandSafety.ServiceRestart)]
    [InlineData("systemctl disable telnet", CommandSafety.ServiceRestart)]
    [InlineData("service sshd restart", CommandSafety.ServiceRestart)]
    public void Classify_ServiceCommands_ReturnsServiceRestart(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Theory]
    [InlineData("rm -rf /etc/nginx", CommandSafety.Destructive)]
    [InlineData("iptables -F", CommandSafety.Destructive)]
    [InlineData("nft flush ruleset", CommandSafety.Destructive)]
    [InlineData("nft delete rule ip filter input handle 10", CommandSafety.Destructive)]
    [InlineData("dd if=/dev/zero of=/dev/sda", CommandSafety.Destructive)]
    [InlineData("mkfs.ext4 /dev/sdb1", CommandSafety.Destructive)]
    public void Classify_DestructiveCommands_ReturnsDestructive(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Theory]
    [InlineData("", CommandSafety.Unknown)]
    [InlineData("   ", CommandSafety.Unknown)]
    [InlineData("some-random-command", CommandSafety.Unknown)]
    public void Classify_UnknownOrEmpty_ReturnsUnknown(string command, CommandSafety expected)
    {
        Assert.Equal(expected, CommandSafetyClassifier.Classify(command));
    }

    [Fact]
    public void Classify_DestructiveOverridesConfigChange()
    {
        // iptables -F is destructive, not just config change
        Assert.Equal(CommandSafety.Destructive, CommandSafetyClassifier.Classify("iptables -F"));
    }
}
