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
}
