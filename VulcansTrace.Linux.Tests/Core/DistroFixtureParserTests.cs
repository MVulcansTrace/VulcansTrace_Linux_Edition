using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class DistroFixtureParserTests
{
    private static readonly string FixtureRoot = Path.Combine("Data", "DistroFixtures");

    public static IEnumerable<object[]> DistroDirectories()
    {
        var root = Path.Combine(AppContext.BaseDirectory, FixtureRoot);
        if (!Directory.Exists(root))
        {
            // Try from source tree during dotnet test
            root = Path.Combine(Directory.GetCurrentDirectory(), FixtureRoot);
        }

        if (!Directory.Exists(root))
            yield break;

        foreach (var dir in Directory.GetDirectories(root).OrderBy(d => d))
        {
            yield return new object[] { Path.GetFileName(dir)! };
        }
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void PortScanner_Parses_Without_Error(string distro)
    {
        var path = GetFixturePath(distro, "ss-tulnp.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        PortScanner.ParseOutput(output, builder);
        var data = builder.Build();

        // Should parse without throwing and produce reasonable data
        Assert.NotNull(data.OpenPorts);
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void ServiceScanner_Parses_Without_Error(string distro)
    {
        var path = GetFixturePath(distro, "systemctl-list-units.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        ServiceScanner.ParseOutput(output, builder);
        var data = builder.Build();

        Assert.NotNull(data.RunningServices);
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void NetworkScanner_Addresses_Parses_Without_Error(string distro)
    {
        var path = GetFixturePath(distro, "ip-addr.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        NetworkScanner.ParseAddresses(output, builder);
        var data = builder.Build();

        Assert.NotNull(data.NetworkInterfaces);
        // Most systems should have at least a loopback interface
        Assert.True(data.NetworkInterfaces.Count > 0, $"{distro}: Expected at least one network interface");
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void NetworkScanner_Routes_Parses_Without_Error(string distro)
    {
        var path = GetFixturePath(distro, "ip-route.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        NetworkScanner.ParseRoutes(output, builder);
        var data = builder.Build();

        Assert.NotNull(data.Routes);
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void FirewallScanner_Parses_Without_Error(string distro)
    {
        var iptablesPath = GetFixturePath(distro, "iptables-L-n-v.txt");
        var nftPath = GetFixturePath(distro, "nft-list-ruleset.txt");

        if (!File.Exists(iptablesPath) && !File.Exists(nftPath))
        {
            // Some distros might not have firewall fixtures (e.g., containers)
            return;
        }

        var builder = new ScanDataBuilder();

        if (File.Exists(iptablesPath))
        {
            var output = File.ReadAllText(iptablesPath);
            FirewallScanner.ParseIptables(output, builder);
        }
        else if (File.Exists(nftPath))
        {
            var output = File.ReadAllText(nftPath);
            FirewallScanner.ParseNftables(output, builder);
        }

        var data = builder.Build();
        Assert.NotNull(data.FirewallRules);
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void PortScanner_Produces_Reasonable_Data(string distro)
    {
        var path = GetFixturePath(distro, "ss-tulnp.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        PortScanner.ParseOutput(output, builder);
        var data = builder.Build();

        // Should find at least one open port in all our fixtures
        Assert.True(data.OpenPorts.Count > 0, $"{distro}: Expected at least one open port");

        // Verify SSH port 22 is found in most fixtures (except containers which might not have it)
        if (distro != "containers")
        {
            Assert.Contains(data.OpenPorts, p => p.LocalPort == 22);
        }
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void NetworkScanner_Addresses_Produce_Reasonable_Data(string distro)
    {
        var path = GetFixturePath(distro, "ip-addr.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        NetworkScanner.ParseAddresses(output, builder);
        var data = builder.Build();

        // Should find loopback interface
        Assert.Contains(data.NetworkInterfaces, i => i.Name == "lo");

        // Should find at least one interface that is up
        Assert.Contains(data.NetworkInterfaces, i => i.IsUp);
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void NetworkScanner_Routes_Produce_Reasonable_Data(string distro)
    {
        var path = GetFixturePath(distro, "ip-route.txt");
        Assert.True(File.Exists(path), $"Fixture {path} not found");

        var output = File.ReadAllText(path);
        var builder = new ScanDataBuilder();

        NetworkScanner.ParseRoutes(output, builder);
        var data = builder.Build();

        // Should find a default route
        Assert.Contains(data.Routes, r => r.Destination == "default" || r.Destination == "0.0.0.0/0");
    }

    [Theory]
    [MemberData(nameof(DistroDirectories))]
    public void FirewallScanner_Produces_Reasonable_Data(string distro)
    {
        var iptablesPath = GetFixturePath(distro, "iptables-L-n-v.txt");
        var nftPath = GetFixturePath(distro, "nft-list-ruleset.txt");

        if (!File.Exists(iptablesPath) && !File.Exists(nftPath))
        {
            return;
        }

        var builder = new ScanDataBuilder();

        if (File.Exists(iptablesPath))
        {
            var output = File.ReadAllText(iptablesPath);
            FirewallScanner.ParseIptables(output, builder);
            builder.FirewallRaw = output;
            builder.FirewallActive = true;
        }
        else if (File.Exists(nftPath))
        {
            var output = File.ReadAllText(nftPath);
            FirewallScanner.ParseNftables(output, builder);
            builder.FirewallRaw = output;
            builder.FirewallActive = true;
        }

        var data = builder.Build();

        // Should have firewall rules or at least be marked active
        Assert.True(data.FirewallActive, $"{distro}: Expected firewall to be active");
        Assert.True(data.FirewallRules.Count > 0, $"{distro}: Expected at least one firewall rule");
    }

    [Fact]
    public void All_Distro_Fixtures_Exist()
    {
        var expected = new[] { "ubuntu", "debian", "fedora", "rhel", "arch", "containers", "ufw", "firewalld" };
        var root = Path.Combine(AppContext.BaseDirectory, FixtureRoot);
        if (!Directory.Exists(root))
        {
            root = Path.Combine(Directory.GetCurrentDirectory(), FixtureRoot);
        }

        Assert.True(Directory.Exists(root), $"Fixture root not found: {root}");

        var actual = Directory.GetDirectories(root).Select(Path.GetFileName).OrderBy(n => n).ToList();
        foreach (var distro in expected)
        {
            Assert.Contains(distro, actual);
        }
    }

    private static string GetFixturePath(string distro, string filename)
    {
        var baseDir = AppContext.BaseDirectory;
        var path = Path.Combine(baseDir, FixtureRoot, distro, filename);
        if (File.Exists(path))
            return path;

        // Fallback to source tree path during dotnet test
        return Path.Combine(Directory.GetCurrentDirectory(), FixtureRoot, distro, filename);
    }
}
