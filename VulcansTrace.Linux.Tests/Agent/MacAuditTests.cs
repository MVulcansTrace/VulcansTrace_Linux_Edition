using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class MacAuditTests
{
    #region Scanner parsing

    [Fact]
    public void ParseAppArmorStatus_ComplainAndEnforceAndUnconfined_PopulatesLists()
    {
        var output = """
            AppArmor status: enabled
            2 profiles are in complain mode.
                /usr/bin/man
                /usr/sbin/nscd (complain)
            3 profiles are in enforce mode.
                /usr/sbin/dnsmasq
                /usr/sbin/mysqld (enforce)
                /usr/sbin/sssd
            2 processes are unconfined but have a profile defined.
                /usr/sbin/nscd 1234
            """;

        var complain = new List<string>();
        var enforce = new List<string>();
        var unconfined = new List<string>();

        MacScanner.ParseAppArmorStatus(output, complain, enforce, unconfined);

        Assert.Equal(2, complain.Count);
        Assert.Contains("/usr/bin/man", complain);
        Assert.Contains("/usr/sbin/nscd", complain);

        Assert.Equal(3, enforce.Count);
        Assert.Contains("/usr/sbin/dnsmasq", enforce);
        Assert.Contains("/usr/sbin/mysqld", enforce);
        Assert.Contains("/usr/sbin/sssd", enforce);

        Assert.Single(unconfined);
        Assert.Contains("/usr/sbin/nscd 1234", unconfined);
    }

    [Fact]
    public void ParseAppArmorStatus_RealOutputWithZeroUnconfined_LeavesUnconfinedEmpty()
    {
        // Real `aa-status` emits per-mode process count summaries after
        // "processes have profiles defined."; these must NOT be bucketed as unconfined.
        var output = """
            apparmor module is loaded.
            8 profiles are loaded.
            5 profiles are in enforce mode.
               /usr/sbin/mysqld (enforce)
            3 profiles are in complain mode.
               /usr/bin/man (complain)
            3 processes have profiles defined.
            2 processes are in enforce mode.
            1 processes are in complain mode.
            0 processes are unconfined but have a profile defined.
            """;

        var complain = new List<string>();
        var enforce = new List<string>();
        var unconfined = new List<string>();

        MacScanner.ParseAppArmorStatus(output, complain, enforce, unconfined);

        Assert.Empty(unconfined);
        Assert.Contains("/usr/sbin/mysqld", enforce);
        Assert.Contains("/usr/bin/man", complain);
    }

    [Fact]
    public void ParseAppArmorStatus_RealOutputWithUnconfinedProcesses_CollectsPaths()
    {
        var output = """
            apparmor module is loaded.
            2 profiles are loaded.
            1 profiles are in enforce mode.
               /usr/sbin/mysqld (enforce)
            1 processes have profiles defined.
            1 processes are in enforce mode.
            0 processes are in complain mode.
            1 processes are unconfined but have a profile defined.
               /usr/sbin/vulnerable (4242)
            """;

        var complain = new List<string>();
        var enforce = new List<string>();
        var unconfined = new List<string>();

        MacScanner.ParseAppArmorStatus(output, complain, enforce, unconfined);

        Assert.Single(unconfined);
        Assert.Contains("/usr/sbin/vulnerable (4242)", unconfined);
    }

    [Theory]
    [InlineData("Y", true)]
    [InlineData("1", true)]
    [InlineData("enabled", true)]
    [InlineData("N", false)]
    [InlineData("0", false)]
    [InlineData("disabled", false)]
    public void ParseAppArmorEnabledValue_ParsesKnownValues(string value, bool expected)
    {
        Assert.Equal(expected, MacScanner.ParseAppArmorEnabledValue(value));
    }

    [Fact]
    public void AppArmorStatusReportsProfilesInMode_EnforceCount_ReturnsTrue()
    {
        var output = """
            apparmor module is loaded.
            8 profiles are loaded.
            5 profiles are in enforce mode.
            3 profiles are in complain mode.
            """;

        Assert.True(MacScanner.AppArmorStatusReportsProfilesInMode(output, "enforce"));
        Assert.True(MacScanner.AppArmorStatusReportsProfilesInMode(output, "complain"));
    }

    [Fact]
    public void AppArmorStatusReportsProfilesInMode_ZeroCount_ReturnsFalse()
    {
        var output = """
            apparmor module is loaded.
            0 profiles are in enforce mode.
            """;

        Assert.False(MacScanner.AppArmorStatusReportsProfilesInMode(output, "enforce"));
    }

    [Fact]
    public void ReadSelinuxConfigMode_Enforcing_ReturnsEnforcing()
    {
        var temp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(temp, """
                # This file controls the state of SELinux on the system.
                SELINUX=enforcing
                SELINUXTYPE=targeted
                """);

            var mode = MacScanner.ReadSelinuxConfigMode(temp);

            Assert.Equal("enforcing", mode);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void ReadSelinuxConfigMode_Permissive_ReturnsPermissive()
    {
        var temp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(temp, "SELINUX=permissive\n");

            var mode = MacScanner.ReadSelinuxConfigMode(temp);

            Assert.Equal("permissive", mode);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void ReadSelinuxConfigMode_MissingFile_ReturnsDisabled()
    {
        var mode = MacScanner.ReadSelinuxConfigMode(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));

        Assert.Equal("disabled", mode);
    }

    #endregion

    #region MAC-001 Framework active

    [Fact]
    public void MacFrameworkActiveRule_AppArmorEnforcing_Passes()
    {
        var rule = new MacFrameworkActiveRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = true,
                AppArmorEnforcing = true,
                SelinuxInstalled = false,
                SelinuxMode = "disabled"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MacFrameworkActiveRule_SelinuxEnforcing_Passes()
    {
        var rule = new MacFrameworkActiveRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = false,
                AppArmorEnforcing = false,
                SelinuxInstalled = true,
                SelinuxMode = "enforcing"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MacFrameworkActiveRule_BothInactive_Fails()
    {
        var rule = new MacFrameworkActiveRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = true,
                AppArmorEnforcing = false,
                SelinuxInstalled = true,
                SelinuxMode = "permissive"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void MacFrameworkActiveRule_NoMacInstalled_PassesAsNotReadable()
    {
        var rule = new MacFrameworkActiveRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = false,
                AppArmorInstalled = false,
                SelinuxInstalled = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MacFrameworkActiveRule_MissingConfig_Passes()
    {
        var rule = new MacFrameworkActiveRule();
        var result = rule.Evaluate(new ScanData());

        Assert.True(result.Passed);
    }

    #endregion

    #region MAC-002 AppArmor unconfined

    [Fact]
    public void MacAppArmorUnconfinedRule_NoUnconfined_Passes()
    {
        var rule = new MacAppArmorUnconfinedRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = true,
                AppArmorUnconfined = Array.Empty<string>()
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MacAppArmorUnconfinedRule_UnconfinedExists_Fails()
    {
        var rule = new MacAppArmorUnconfinedRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = true,
                AppArmorUnconfined = new[] { "/usr/sbin/nscd 1234" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void MacAppArmorUnconfinedRule_AppArmorNotInstalled_NotApplicable()
    {
        var rule = new MacAppArmorUnconfinedRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                AppArmorInstalled = false,
                SelinuxInstalled = true,
                SelinuxMode = "enforcing"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    #endregion

    #region MAC-003 SELinux enforcing

    [Fact]
    public void MacSelinuxEnforcingRule_Enforcing_Passes()
    {
        var rule = new MacSelinuxEnforcingRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                SelinuxInstalled = true,
                SelinuxMode = "enforcing"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MacSelinuxEnforcingRule_Permissive_Fails()
    {
        var rule = new MacSelinuxEnforcingRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                SelinuxInstalled = true,
                SelinuxMode = "permissive"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
        Assert.Equal("permissive", result.Variables["mode"]);
    }

    [Fact]
    public void MacSelinuxEnforcingRule_SelinuxNotInstalled_NotApplicable()
    {
        var rule = new MacSelinuxEnforcingRule();
        var data = new ScanData
        {
            MacConfig = new MacConfig
            {
                ConfigReadable = true,
                SelinuxInstalled = false,
                AppArmorInstalled = true,
                AppArmorEnforcing = true
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    #endregion
}
