using System.Collections.Immutable;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RuleTests
{
    [Fact]
    public void FirewallActiveRule_NoFirewall_Fails()
    {
        var rule = new FirewallActiveRule();
        var data = new ScanData { FirewallActive = false, FirewallRules = Array.Empty<FirewallRule>() };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void FirewallActiveRule_FirewallActive_Passes()
    {
        var rule = new FirewallActiveRule();
        var data = new ScanData
        {
            FirewallActive = true,
            FirewallRules = new[] { new FirewallRule { Chain = "INPUT", Target = "DROP" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void FirewallDefaultDropRule_AcceptPolicy_Fails()
    {
        var rule = new FirewallDefaultDropRule();
        var data = new ScanData
        {
            FirewallActive = true,
            FirewallRaw = "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)",
            FirewallRules = new[] { new FirewallRule { Chain = "INPUT", Target = "ACCEPT" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void FirewallDefaultDropRule_DropPolicy_Passes()
    {
        var rule = new FirewallDefaultDropRule();
        var data = new ScanData
        {
            FirewallActive = true,
            FirewallRaw = "Chain INPUT (policy DROP 0 packets, 0 bytes)",
            FirewallRules = Array.Empty<FirewallRule>()
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void TelnetServiceRule_TelnetRunning_Fails()
    {
        var rule = new TelnetServiceRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "telnet.socket", State = "running" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void TelnetServiceRule_NoTelnet_Passes()
    {
        var rule = new TelnetServiceRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "sshd.service", State = "running" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void DatabasePortExposureRule_DbExposed_Fails()
    {
        var rule = new DatabasePortExposureRule();
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 3306, State = "LISTEN", ProcessName = "mysqld" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void DatabasePortExposureRule_DbLocalOnly_Passes()
    {
        var rule = new DatabasePortExposureRule();
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "127.0.0.1", LocalPort = 3306, State = "LISTEN", ProcessName = "mysqld" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void DefaultRouteRule_NoRoute_Fails()
    {
        var rule = new DefaultRouteRule();
        var data = new ScanData { Routes = Array.Empty<RouteEntry>() };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void DefaultRouteRule_HasRoute_Passes()
    {
        var rule = new DefaultRouteRule();
        var data = new ScanData
        {
            Routes = new[] { new RouteEntry { Destination = "default", Gateway = "192.168.1.1", Interface = "eth0" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshServiceRule_NoSsh_Fails()
    {
        var rule = new SshServiceRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "nginx.service", State = "running" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SshServiceRule_SshRunning_Passes()
    {
        var rule = new SshServiceRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "ssh.service", State = "running" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshNonDefaultPortRule_Workstation_PassesOnDefaultPort()
    {
        var rule = new SshNonDefaultPortRule();
        var data = new ScanData
        {
            OpenPorts = new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN", ProcessName = "sshd" } }
        };
        var context = new RuleEvaluationContext(MachineRole.Workstation,
            new RulePolicy { Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Pass" }.ToImmutableDictionary() });

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshNonDefaultPortRule_Server_FailsOnDefaultPort()
    {
        var rule = new SshNonDefaultPortRule();
        var data = new ScanData
        {
            OpenPorts = new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN", ProcessName = "sshd" } }
        };
        var context = new RuleEvaluationContext(MachineRole.Server,
            new RulePolicy { Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Fail" }.ToImmutableDictionary() });

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
    }

    [Fact]
    public void WideOpenServicesRule_Default_FailsOn8080()
    {
        var rule = new WideOpenServicesRule();
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 8080, State = "LISTEN", ProcessName = "node" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void WideOpenServicesRule_DevMachine_AllowsExtraPorts()
    {
        var rule = new WideOpenServicesRule();
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 8080, State = "LISTEN", ProcessName = "node" }
            }
        };
        var context = new RuleEvaluationContext(MachineRole.DevMachine,
            new RulePolicy { Parameters = new Dictionary<string, string> { ["expectedPublicPorts"] = "22,80,443,8080,8443" }.ToImmutableDictionary() });

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void UnnecessaryServicesRule_Default_FailsOnNfs()
    {
        var rule = new UnnecessaryServicesRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "nfs-server.service", State = "running" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void UnnecessaryServicesRule_DevMachine_IgnoresConfiguredServices()
    {
        var rule = new UnnecessaryServicesRule();
        var data = new ScanData
        {
            RunningServices = new[] { new RunningService { Name = "nfs-server.service", State = "running" } }
        };
        var context = new RuleEvaluationContext(MachineRole.DevMachine,
            new RulePolicy { Parameters = new Dictionary<string, string> { ["ignoredServices"] = "nfs,smb" }.ToImmutableDictionary() });

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    // =====================================================================
    // SSH Rules
    // =====================================================================

    [Fact]
    public void SshPermitRootLoginRule_Yes_Fails()
    {
        var rule = new SshPermitRootLoginRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PermitRootLogin = "yes" } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SshPermitRootLoginRule_No_Passes()
    {
        var rule = new SshPermitRootLoginRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PermitRootLogin = "no" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshPermitRootLoginRule_ProhibitPassword_Passes()
    {
        var rule = new SshPermitRootLoginRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PermitRootLogin = "prohibit-password" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshPasswordAuthenticationRule_Yes_Fails()
    {
        var rule = new SshPasswordAuthenticationRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PasswordAuthentication = "yes" } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SshPasswordAuthenticationRule_No_Passes()
    {
        var rule = new SshPasswordAuthenticationRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PasswordAuthentication = "no" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshMaxAuthTriesRule_High_Fails()
    {
        var rule = new SshMaxAuthTriesRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, MaxAuthTries = 6 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SshMaxAuthTriesRule_Null_Fails()
    {
        var rule = new SshMaxAuthTriesRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, MaxAuthTries = null } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void SshMaxAuthTriesRule_Low_Passes()
    {
        var rule = new SshMaxAuthTriesRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, MaxAuthTries = 3 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshProtocolRule_Protocol1_Fails()
    {
        var rule = new SshProtocolRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, Protocol = "1,2" } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SshProtocolRule_Protocol2_Passes()
    {
        var rule = new SshProtocolRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, Protocol = "2" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshProtocolRule_Null_Passes()
    {
        var rule = new SshProtocolRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, Protocol = null } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshProtocolRule_Protocol12_DoesNotFalsePositive()
    {
        var rule = new SshProtocolRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, Protocol = "12" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshProtocolRule_Protocol21_DoesNotFalsePositive()
    {
        var rule = new SshProtocolRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, Protocol = "21" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshMaxAuthTriesRule_Zero_Fails()
    {
        var rule = new SshMaxAuthTriesRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, MaxAuthTries = 0 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void SshEmptyPasswordsRule_Yes_Fails()
    {
        var rule = new SshEmptyPasswordsRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PermitEmptyPasswords = "yes" } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SshEmptyPasswordsRule_No_Passes()
    {
        var rule = new SshEmptyPasswordsRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PermitEmptyPasswords = "no" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshPubkeyAuthenticationRule_No_Fails()
    {
        var rule = new SshPubkeyAuthenticationRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PubkeyAuthentication = "no" } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SshPubkeyAuthenticationRule_Yes_Passes()
    {
        var rule = new SshPubkeyAuthenticationRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, PubkeyAuthentication = "yes" } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshX11ForwardingRule_ServerYes_Fails()
    {
        var rule = new SshX11ForwardingRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, X11Forwarding = "yes" } };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SshX11ForwardingRule_WorkstationYes_Passes()
    {
        var rule = new SshX11ForwardingRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, X11Forwarding = "yes" } };
        var context = new RuleEvaluationContext(MachineRole.Workstation, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshX11ForwardingRule_ServerNo_Passes()
    {
        var rule = new SshX11ForwardingRule();
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = true, X11Forwarding = "no" } };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshRules_NoConfig_Passes()
    {
        var data = new ScanData { SshConfig = null };

        Assert.True(new SshPermitRootLoginRule().Evaluate(data).Passed);
        Assert.True(new SshPasswordAuthenticationRule().Evaluate(data).Passed);
        Assert.True(new SshMaxAuthTriesRule().Evaluate(data).Passed);
        Assert.True(new SshProtocolRule().Evaluate(data).Passed);
        Assert.True(new SshEmptyPasswordsRule().Evaluate(data).Passed);
        Assert.True(new SshPubkeyAuthenticationRule().Evaluate(data).Passed);
        Assert.True(new SshX11ForwardingRule().Evaluate(data).Passed);
    }

    [Fact]
    public void SshRules_ConfigNotReadable_Passes()
    {
        var data = new ScanData { SshConfig = new SshConfig { ConfigReadable = false } };

        Assert.True(new SshPermitRootLoginRule().Evaluate(data).Passed);
        Assert.True(new SshPasswordAuthenticationRule().Evaluate(data).Passed);
        Assert.True(new SshMaxAuthTriesRule().Evaluate(data).Passed);
        Assert.True(new SshProtocolRule().Evaluate(data).Passed);
        Assert.True(new SshEmptyPasswordsRule().Evaluate(data).Passed);
        Assert.True(new SshPubkeyAuthenticationRule().Evaluate(data).Passed);
        Assert.True(new SshX11ForwardingRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // File Permission Rules
    // =====================================================================

    [Fact]
    public void ShadowPermissionRule_Correct_Passes()
    {
        var rule = new ShadowPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/shadow", Mode = "640", Owner = "root", Group = "shadow", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void ShadowPermissionRule_TooPermissive_Fails()
    {
        var rule = new ShadowPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/shadow", Mode = "644", Owner = "root", Group = "root", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void PasswdPermissionRule_Correct_Passes()
    {
        var rule = new PasswdPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/passwd", Mode = "644", Owner = "root", Group = "root", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void PasswdPermissionRule_WrongMode_Fails()
    {
        var rule = new PasswdPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/passwd", Mode = "664", Owner = "root", Group = "root", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
    }

    [Fact]
    public void SshHostKeyPermissionRule_Correct_Passes()
    {
        var rule = new SshHostKeyPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/etc/ssh/ssh_host_rsa_key", Mode = "600", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void SshHostKeyPermissionRule_TooPermissive_Fails()
    {
        var rule = new SshHostKeyPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/etc/ssh/ssh_host_rsa_key", Mode = "644", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void RootSshDirectoryPermissionRule_Correct_Passes()
    {
        var rule = new RootSshDirectoryPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/root/.ssh", Mode = "700", Owner = "root", Group = "root", Exists = true },
                new FilePermissionEntry { Path = "/root/.ssh/authorized_keys", Mode = "600", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void RootSshDirectoryPermissionRule_DirTooPermissive_Fails()
    {
        var rule = new RootSshDirectoryPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/root/.ssh", Mode = "755", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
    }

    [Fact]
    public void CronDirectoryWorldWritableRule_Safe_Passes()
    {
        var rule = new CronDirectoryWorldWritableRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/etc/cron.d", Mode = "755", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void CronDirectoryWorldWritableRule_WorldWritable_Fails()
    {
        var rule = new CronDirectoryWorldWritableRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/etc/cron.d", Mode = "777", Owner = "root", Group = "root", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void CrontabPermissionRule_Correct_Passes()
    {
        var rule = new CrontabPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/crontab", Mode = "644", Owner = "root", Group = "root", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void CrontabPermissionRule_WrongOwner_Fails()
    {
        var rule = new CrontabPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[] { new FilePermissionEntry { Path = "/etc/crontab", Mode = "644", Owner = "user", Group = "root", Exists = true } }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
    }

    [Fact]
    public void UserSshDirectoryPermissionRule_Correct_Passes()
    {
        var rule = new UserSshDirectoryPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/home/alice/.ssh", Mode = "700", Owner = "alice", Group = "alice", Exists = true },
                new FilePermissionEntry { Path = "/home/alice/.ssh/authorized_keys", Mode = "600", Owner = "alice", Group = "alice", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.True(result.Passed);
    }

    [Fact]
    public void UserSshDirectoryPermissionRule_TooPermissive_Fails()
    {
        var rule = new UserSshDirectoryPermissionRule();
        var data = new ScanData
        {
            FilePermissions = new[]
            {
                new FilePermissionEntry { Path = "/home/alice/.ssh", Mode = "755", Owner = "alice", Group = "alice", Exists = true }
            }
        };

        var result = rule.Evaluate(data);
        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void FilePermissionRules_MissingData_Passes()
    {
        var data = new ScanData { FilePermissions = Array.Empty<FilePermissionEntry>() };

        Assert.True(new ShadowPermissionRule().Evaluate(data).Passed);
        Assert.True(new PasswdPermissionRule().Evaluate(data).Passed);
        Assert.True(new SshHostKeyPermissionRule().Evaluate(data).Passed);
        Assert.True(new RootSshDirectoryPermissionRule().Evaluate(data).Passed);
        Assert.True(new CronDirectoryWorldWritableRule().Evaluate(data).Passed);
        Assert.True(new CrontabPermissionRule().Evaluate(data).Passed);
        Assert.True(new UserSshDirectoryPermissionRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // CIS Benchmark Mapping
    // =====================================================================

    [Theory]
    [InlineData(typeof(FirewallDefaultDropRule), "CIS 4.5")]
    [InlineData(typeof(FirewallSshExposureRule), "CIS 4.5")]
    [InlineData(typeof(FirewallStateTrackingRule), "CIS 4.5")]
    [InlineData(typeof(FirewallActiveRule), "CIS 4.5")]
    [InlineData(typeof(FirewallIcmpRule), "CIS 4.5")]
    [InlineData(typeof(DefaultRouteRule), "CIS 4.1")]
    [InlineData(typeof(SuspiciousConnectionsRule), "CIS 13.3")]
    [InlineData(typeof(NetworkInterfaceUpRule), "CIS 4.1")]
    [InlineData(typeof(LoopbackExposureRule), "CIS 4.1")]
    [InlineData(typeof(SshNonDefaultPortRule), "CIS 4.8")]
    [InlineData(typeof(WideOpenServicesRule), "CIS 4.1")]
    [InlineData(typeof(DatabasePortExposureRule), "CIS 4.1")]
    [InlineData(typeof(HighPortListeningRule), "CIS 13.3")]
    [InlineData(typeof(TelnetServiceRule), "CIS 4.8")]
    [InlineData(typeof(FtpServiceRule), "CIS 4.8")]
    [InlineData(typeof(SshServiceRule), "CIS 4.1")]
    [InlineData(typeof(LegacyRservicesRule), "CIS 4.8")]
    [InlineData(typeof(UnnecessaryServicesRule), "CIS 4.8")]
    [InlineData(typeof(SshPermitRootLoginRule), "CIS 5.4")]
    [InlineData(typeof(SshPasswordAuthenticationRule), "CIS 6.3")]
    [InlineData(typeof(SshMaxAuthTriesRule), "CIS 6.3")]
    [InlineData(typeof(SshProtocolRule), "CIS 4.8")]
    [InlineData(typeof(SshEmptyPasswordsRule), "CIS 5.2")]
    [InlineData(typeof(SshPubkeyAuthenticationRule), "CIS 6.3")]
    [InlineData(typeof(SshX11ForwardingRule), "CIS 4.8")]
    [InlineData(typeof(ShadowPermissionRule), "CIS 6.1")]
    [InlineData(typeof(PasswdPermissionRule), "CIS 6.1")]
    [InlineData(typeof(SshHostKeyPermissionRule), "CIS 5.2")]
    [InlineData(typeof(RootSshDirectoryPermissionRule), "CIS 5.2")]
    [InlineData(typeof(CronDirectoryWorldWritableRule), "CIS 6.1")]
    [InlineData(typeof(CrontabPermissionRule), "CIS 6.1")]
    [InlineData(typeof(UserSshDirectoryPermissionRule), "CIS 5.2")]
    public void KeyRules_HaveCisMappings(Type ruleType, string expectedControlId)
    {
        var rule = (IRule)Activator.CreateInstance(ruleType)!;

        Assert.NotEmpty(rule.CisMappings);
        Assert.Contains(rule.CisMappings, m => m.ControlId == expectedControlId);
        Assert.All(rule.CisMappings, m =>
        {
            Assert.False(string.IsNullOrWhiteSpace(m.ControlName));
            Assert.False(string.IsNullOrWhiteSpace(m.WhyItMatters));
        });
    }

    [Fact]
    public void CisMappings_FlowThrough_ToFailedResult()
    {
        var rule = new FirewallActiveRule();
        var data = new ScanData { FirewallActive = false, FirewallRules = Array.Empty<FirewallRule>() };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.NotEmpty(result.CisMappings);
        Assert.Equal(rule.CisMappings, result.CisMappings);
    }

    [Fact]
    public void CisMappings_FlowThrough_ToPassedResult()
    {
        var rule = new FirewallActiveRule();
        var data = new ScanData
        {
            FirewallActive = true,
            FirewallRules = new[] { new FirewallRule { Chain = "INPUT", Target = "DROP" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.NotEmpty(result.CisMappings);
        Assert.Equal(rule.CisMappings, result.CisMappings);
    }
}
