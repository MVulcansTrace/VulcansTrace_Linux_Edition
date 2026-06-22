using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Dialogue;

public class DiagnosticQuestionBankTests
{
    private readonly DiagnosticQuestionBank _bank = new();

    [Theory]
    [InlineData("FW", RuleStatusTrend.Stable, 2)]
    [InlineData("Firewall", RuleStatusTrend.Stable, 3)]
    [InlineData("iptables", RuleStatusTrend.Stable, 2)]
    public void GetQuestion_FirewallWithCycles_ReturnsConfigManagementQuestion(string category, RuleStatusTrend trend, int cycles)
    {
        var question = _bank.GetQuestion(category, trend, cycles);

        Assert.NotNull(question);
        Assert.Contains("config-management", question);
        Assert.Contains("Ansible", question);
    }

    [Theory]
    [InlineData("FW", RuleStatusTrend.Worsening, 0)]
    [InlineData("Firewall", RuleStatusTrend.Worsening, 1)]
    public void GetQuestion_FirewallWorsening_ReturnsWorseningQuestion(string category, RuleStatusTrend trend, int cycles)
    {
        var question = _bank.GetQuestion(category, trend, cycles);

        Assert.NotNull(question);
        Assert.Contains("getting worse", question);
        Assert.Contains("reboot", question);
    }

    [Fact]
    public void GetQuestion_SshWithCycles_ReturnsTemplateQuestion()
    {
        var question = _bank.GetQuestion("SSH", RuleStatusTrend.Stable, 2);

        Assert.NotNull(question);
        Assert.Contains("cloud image template", question);
        Assert.Contains("sshd_config", question);
    }

    [Fact]
    public void GetQuestion_KernelWithCycles_ReturnsSysctlQuestion()
    {
        var question = _bank.GetQuestion("Kernel", RuleStatusTrend.Stable, 2);

        Assert.NotNull(question);
        Assert.Contains("sysctl", question);
        Assert.Contains("/etc/sysctl.d/", question);
    }

    [Fact]
    public void GetQuestion_UserWithCycles_ReturnsIdentityManagementQuestion()
    {
        var question = _bank.GetQuestion("User", RuleStatusTrend.Stable, 2);

        Assert.NotNull(question);
        Assert.Contains("identity-management", question);
        Assert.Contains("cloud-init", question);
    }

    [Fact]
    public void GetQuestion_NoRecurrence_ReturnsNull()
    {
        var question = _bank.GetQuestion("FW", RuleStatusTrend.Stable, 1);

        Assert.Null(question);
    }

    [Fact]
    public void GetQuestion_UnknownCategoryWithCycles_ReturnsGenericQuestion()
    {
        var question = _bank.GetQuestion("Misc", RuleStatusTrend.Stable, 2);

        Assert.NotNull(question);
        Assert.Contains("config-management", question);
        Assert.Contains("base image", question);
    }
}
