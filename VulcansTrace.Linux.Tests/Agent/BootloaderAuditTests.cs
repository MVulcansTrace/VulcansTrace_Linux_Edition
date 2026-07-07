using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class BootloaderAuditTests
{
    #region Scanner parsing

    [Fact]
    public void CmdlineContains_ExactParameter_ReturnsTrue()
    {
        Assert.True(BootloaderScanner.CmdlineContains("BOOT_IMAGE=/vmlinuz quiet splash", "quiet"));
        Assert.True(BootloaderScanner.CmdlineContains("BOOT_IMAGE=/vmlinuz single", "single"));
    }

    [Fact]
    public void CmdlineContains_MissingParameter_ReturnsFalse()
    {
        Assert.False(BootloaderScanner.CmdlineContains("BOOT_IMAGE=/vmlinuz quiet", "single"));
    }

    [Fact]
    public void CmdlineContainsPattern_PrefixMatch_ReturnsTrue()
    {
        Assert.True(BootloaderScanner.CmdlineContainsPattern("BOOT_IMAGE=/vmlinuz modules_disabled=1", "modules_disabled="));
        Assert.True(BootloaderScanner.CmdlineContainsPattern("BOOT_IMAGE=/vmlinuz module.sig_enforce=1", "module.sig_enforce="));
    }

    [Fact]
    public async Task ScanAsync_ParsesGrubVariables()
    {
        var temp = Path.GetTempFileName();
        var grubD = Directory.CreateTempSubdirectory();
        try
        {
            File.WriteAllText(temp, """
                GRUB_DEFAULT=0
                GRUB_TIMEOUT=5
                GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
                #GRUB_HIDDEN_TIMEOUT=0
                """);

            var config = await BootloaderScanner.ScanAsync(temp, grubD.FullName, CancellationToken.None);

            Assert.True(config.ConfigReadable);
            Assert.Contains("GRUB_DEFAULT", config.GrubVariables);
            Assert.Equal("0", config.GrubVariables["GRUB_DEFAULT"]);
            Assert.Equal("5", config.GrubVariables["GRUB_TIMEOUT"]);
            Assert.Equal("quiet splash", config.GrubVariables["GRUB_CMDLINE_LINUX_DEFAULT"]);
        }
        finally
        {
            File.Delete(temp);
            grubD.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task ScanAsync_ParsesGrubPasswordFromGrubDirectory()
    {
        var temp = Path.GetTempFileName();
        var grubD = Directory.CreateTempSubdirectory();
        try
        {
            File.WriteAllText(temp, "GRUB_TIMEOUT=5\n");
            File.WriteAllText(Path.Combine(grubD.FullName, "40_custom"), "set superusers=\"admin\"\npassword_pbkdf2 admin hash\n");

            var config = await BootloaderScanner.ScanAsync(temp, grubD.FullName, CancellationToken.None);

            Assert.True(config.GrubPasswordConfigured);
        }
        finally
        {
            File.Delete(temp);
            grubD.Delete(recursive: true);
        }
    }

    #endregion

    #region BOOT-001 Secure Boot

    [Fact]
    public void BootloaderSecureBootEnabledRule_Enabled_Passes()
    {
        var rule = new BootloaderSecureBootEnabledRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig { ConfigReadable = true, SecureBootEnabled = true }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void BootloaderSecureBootEnabledRule_Disabled_Fails()
    {
        var rule = new BootloaderSecureBootEnabledRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig { ConfigReadable = true, SecureBootEnabled = false }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void BootloaderSecureBootEnabledRule_Unknown_Passes()
    {
        var rule = new BootloaderSecureBootEnabledRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig { ConfigReadable = true, SecureBootEnabled = null }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    #endregion

    #region BOOT-002 Rescue parameters

    [Theory]
    [InlineData("BOOT_IMAGE=/vmlinuz root=/dev/sda1 single", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz root=/dev/sda1 init=/bin/bash", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz root=/dev/sda1 rd.break", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz root=/dev/sda1 systemd.debug-shell", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet splash", false)]
    public void NoRescueBootParameterRule_Various_ReturnsExpected(string cmdline, bool shouldFail)
    {
        var rule = new NoRescueBootParameterRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig { ConfigReadable = true, KernelCmdline = cmdline }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(!shouldFail, result.Passed);
    }

    #endregion

    #region BOOT-003 GRUB password

    [Fact]
    public void GrubPasswordSetRule_PasswordVariable_Passes()
    {
        var rule = new GrubPasswordSetRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig
            {
                ConfigReadable = true,
                GrubFileExists = true,
                GrubVariables = new Dictionary<string, string> { ["GRUB_PASSWORD"] = "encrypted" },
                GrubPasswordConfigured = true
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void GrubPasswordSetRule_NoPassword_Fails()
    {
        var rule = new GrubPasswordSetRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig
            {
                ConfigReadable = true,
                GrubFileExists = true,
                GrubVariables = new Dictionary<string, string> { ["GRUB_TIMEOUT"] = "5" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void GrubPasswordSetRule_NoGrubFile_Passes()
    {
        var rule = new GrubPasswordSetRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig
            {
                ConfigReadable = true,
                GrubFileExists = false,
                KernelCmdline = "BOOT_IMAGE=/vmlinuz"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    #endregion

    #region BOOT-004 Module load restriction

    [Theory]
    [InlineData("BOOT_IMAGE=/vmlinuz modules_disabled=1", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz module.sig_enforce=1", true)]
    [InlineData("BOOT_IMAGE=/vmlinuz modules_disabled=0", false)]
    [InlineData("BOOT_IMAGE=/vmlinuz module.sig_enforce=0", false)]
    [InlineData("BOOT_IMAGE=/vmlinuz quiet splash", false)]
    public void KernelModuleLoadRestrictionRule_Various_ReturnsExpected(string cmdline, bool shouldPass)
    {
        var rule = new KernelModuleLoadRestrictionRule();
        var data = new ScanData
        {
            BootloaderConfig = new BootloaderConfig { ConfigReadable = true, KernelCmdline = cmdline }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(shouldPass, result.Passed);
    }

    #endregion
}
