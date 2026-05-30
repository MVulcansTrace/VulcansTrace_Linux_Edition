using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ScannerParserFixtureTests
{
    // =====================================================================
    // FirewallScanner Fixtures
    // =====================================================================

    private const string IptablesSample = """
        Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
        pkts bytes target     prot opt in     out     source               destination
           0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
          42  2100 DROP       tcp  --  eth0   *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
          10   500 ACCEPT     tcp  --  *      *       192.168.1.0/24       0.0.0.0/0            tcp dpt:80 state ESTABLISHED,RELATED
        Chain FORWARD (policy DROP 0 packets, 0 bytes)
        pkts bytes target     prot opt in     out     source               destination
           0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0
        Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
        pkts bytes target     prot opt in     out     source               destination
         120  8400 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0
        """;

    private const string NftablesSample = """
        table inet filter {
            chain input {
                type filter hook input priority 0; policy drop;
                iif "lo" accept
                ip saddr 192.168.1.0/24 tcp dport 22 accept
                counter drop
            }
            chain forward {
                type filter hook forward priority 0; policy drop;
                drop
            }
            chain output {
                type filter hook output priority 0; policy accept;
                accept
            }
        }
        """;

    [Fact]
    public void FirewallScanner_ParseIptables_ExtractsChainsAndRules()
    {
        var builder = new ScanDataBuilder();
        FirewallScanner.ParseIptables(IptablesSample, builder);
        var data = builder.Build();

        Assert.True(data.FirewallRules.Count >= 3);

        var inputRules = data.FirewallRules.Where(r => r.Chain == "INPUT").ToList();
        Assert.Equal(3, inputRules.Count);

        var rule0 = inputRules[0];
        Assert.Equal("ACCEPT", rule0.Target);
        Assert.Equal("all", rule0.Protocol);
        Assert.Equal("lo", rule0.InInterface);
        Assert.Equal("0.0.0.0/0", rule0.Source);
        Assert.Equal("0.0.0.0/0", rule0.Destination);

        var rule1 = inputRules[1];
        Assert.Equal("DROP", rule1.Target);
        Assert.Equal("tcp", rule1.Protocol);
        Assert.Equal("eth0", rule1.InInterface);
        Assert.Equal("22", rule1.DestinationPort);

        var rule2 = inputRules[2];
        Assert.Equal("ACCEPT", rule2.Target);
        Assert.Equal("tcp", rule2.Protocol);
        Assert.Equal("80", rule2.DestinationPort);
        Assert.Equal("ESTABLISHED,RELATED", rule2.StateMatch);
    }

    [Fact]
    public void FirewallScanner_ParseIptables_EmptyInput_YieldsNoRules()
    {
        var builder = new ScanDataBuilder();
        FirewallScanner.ParseIptables("", builder);
        var data = builder.Build();

        Assert.Empty(data.FirewallRules);
    }

    [Fact]
    public void FirewallScanner_ParseIptablesRuleLine_ValidLine_ReturnsRule()
    {
        var line = "42 2100 DROP tcp -- eth0 * 0.0.0.0/0 0.0.0.0/0 tcp --dport 22";
        var rule = FirewallScanner.ParseIptablesRuleLine(line, "INPUT");

        Assert.NotNull(rule);
        Assert.Equal("INPUT", rule.Chain);
        Assert.Equal("DROP", rule.Target);
        Assert.Equal("tcp", rule.Protocol);
        Assert.Equal("eth0", rule.InInterface);
        Assert.Equal("0.0.0.0/0", rule.Source);
        Assert.Equal("0.0.0.0/0", rule.Destination);
        Assert.Equal("22", rule.DestinationPort);
    }

    [Fact]
    public void FirewallScanner_ParseIptablesRuleLine_ShortLine_ReturnsNull()
    {
        var rule = FirewallScanner.ParseIptablesRuleLine("42 2100", "INPUT");
        Assert.Null(rule);
    }

    [Fact]
    public void FirewallScanner_ParseNftables_ExtractsRules()
    {
        var builder = new ScanDataBuilder();
        FirewallScanner.ParseNftables(NftablesSample, builder);
        var data = builder.Build();

        Assert.True(data.FirewallRules.Count >= 3);
        Assert.Contains(data.FirewallRules, r => r.Chain == "input");
        Assert.Contains(data.FirewallRules, r => r.Chain == "forward");
        Assert.Contains(data.FirewallRules, r => r.Chain == "output");
    }

    [Fact]
    public void FirewallScanner_ParseNftables_EmptyInput_YieldsNoRules()
    {
        var builder = new ScanDataBuilder();
        FirewallScanner.ParseNftables("", builder);
        var data = builder.Build();

        Assert.Empty(data.FirewallRules);
    }

    // =====================================================================
    // PortScanner Fixtures
    // =====================================================================

    private const string SsSample = """
        Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port Process
        tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
        tcp    LISTEN  0       128     [::]:22             [::]:*            users:(("sshd",pid=1234,fd=4))
        tcp    LISTEN  0       128     127.0.0.1:3306      0.0.0.0:*         users:(("mysqld",pid=567,fd=10))
        udp    UNCONN  0       0       0.0.0.0:68          0.0.0.0:*         users:(("dhclient",pid=89,fd=5))
        tcp    LISTEN  0       128     192.168.1.10:8080   0.0.0.0:*         users:(("java",pid=999,fd=15))
        """;

    private const string NetstatSample = """
        Active Internet connections (only servers)
        Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
        tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
        tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      567/mysqld
        udp        0      0 0.0.0.0:68              0.0.0.0:*                           89/dhclient
        """;

    [Fact]
    public void PortScanner_ParseOutput_SsFormat_ExtractsPorts()
    {
        var builder = new ScanDataBuilder();
        PortScanner.ParseOutput(SsSample, builder);
        var data = builder.Build();

        Assert.Equal(5, data.OpenPorts.Count);

        var ssh = data.OpenPorts.First(p => p.LocalPort == 22 && p.LocalAddress == "0.0.0.0");
        Assert.Equal("tcp", ssh.Protocol);
        Assert.Equal("LISTEN", ssh.State);
        Assert.Equal(1234, ssh.ProcessId);

        var ssh6 = data.OpenPorts.First(p => p.LocalPort == 22 && p.LocalAddress == "::");
        Assert.Equal("tcp", ssh6.Protocol);

        var mysql = data.OpenPorts.First(p => p.LocalPort == 3306);
        Assert.Equal("127.0.0.1", mysql.LocalAddress);
        Assert.Equal(567, mysql.ProcessId);

        var dhclient = data.OpenPorts.First(p => p.LocalPort == 68);
        Assert.Equal("udp", dhclient.Protocol);
        Assert.Equal(89, dhclient.ProcessId);

        var java = data.OpenPorts.First(p => p.LocalPort == 8080);
        Assert.Equal("192.168.1.10", java.LocalAddress);
        Assert.Equal(999, java.ProcessId);
    }

    [Fact]
    public void PortScanner_ParseOutput_NetstatFormat_ExtractsPorts()
    {
        var builder = new ScanDataBuilder();
        PortScanner.ParseOutput(NetstatSample, builder);
        var data = builder.Build();

        Assert.Equal(3, data.OpenPorts.Count);

        var ssh = data.OpenPorts.First(p => p.LocalPort == 22);
        Assert.Equal("tcp", ssh.Protocol);
        Assert.Equal("LISTEN", ssh.State);
        Assert.Equal(1234, ssh.ProcessId);
        Assert.Equal("sshd", ssh.ProcessName);

        var mysql = data.OpenPorts.First(p => p.LocalPort == 3306);
        Assert.Equal("mysqld", mysql.ProcessName);
        Assert.Equal(567, mysql.ProcessId);
    }

    [Fact]
    public void PortScanner_ParseOutput_EmptyInput_YieldsNoPorts()
    {
        var builder = new ScanDataBuilder();
        PortScanner.ParseOutput("", builder);
        var data = builder.Build();

        Assert.Empty(data.OpenPorts);
    }

    [Fact]
    public void PortScanner_ParseAddressPort_Ipv4_ReturnsAddressAndPort()
    {
        var (addr, port) = PortScanner.ParseAddressPort("192.168.1.10:8080");
        Assert.Equal("192.168.1.10", addr);
        Assert.Equal(8080, port);
    }

    [Fact]
    public void PortScanner_ParseAddressPort_Ipv6_ReturnsAddressAndPort()
    {
        var (addr, port) = PortScanner.ParseAddressPort("[::]:22");
        Assert.Equal("::", addr);
        Assert.Equal(22, port);
    }

    [Fact]
    public void PortScanner_ParseAddressPort_NoPort_ReturnsInputAndZero()
    {
        var (addr, port) = PortScanner.ParseAddressPort("192.168.1.10");
        Assert.Equal("192.168.1.10", addr);
        Assert.Equal(0, port);
    }

    [Fact]
    public void PortScanner_ParseProcess_SsUsersFormat_ReturnsPid()
    {
        var (name, pid) = PortScanner.ParseProcess("users:((\"sshd\",pid=1234,fd=3))");
        Assert.Null(name); // ss format doesn't extract name reliably from users:()
        Assert.Equal(1234, pid);
    }

    [Fact]
    public void PortScanner_ParseProcess_NetstatSlashFormat_ReturnsNameAndPid()
    {
        var (name, pid) = PortScanner.ParseProcess("1234/sshd");
        Assert.Equal("sshd", name);
        Assert.Equal(1234, pid);
    }

    // =====================================================================
    // ServiceScanner Fixtures
    // =====================================================================

    private const string SystemctlSample = """
        sshd.service      loaded active running OpenSSH server daemon
        nginx.service     loaded active running A high performance web server and a reverse proxy server
        mysqld.service    loaded active running MySQL Server
        dbus.service      loaded active running D-Bus System Message Bus
        """;

    [Fact]
    public void ServiceScanner_ParseOutput_ExtractsServices()
    {
        var builder = new ScanDataBuilder();
        ServiceScanner.ParseOutput(SystemctlSample, builder);
        var data = builder.Build();

        Assert.Equal(4, data.RunningServices.Count);

        var ssh = data.RunningServices.First(s => s.Name == "sshd.service");
        Assert.Equal("active/running", ssh.State);
        Assert.Equal("OpenSSH server daemon", ssh.Description);

        var nginx = data.RunningServices.First(s => s.Name == "nginx.service");
        Assert.Equal("A high performance web server and a reverse proxy server", nginx.Description);

        var mysql = data.RunningServices.First(s => s.Name == "mysqld.service");
        Assert.Equal("MySQL Server", mysql.Description);

        var dbus = data.RunningServices.First(s => s.Name == "dbus.service");
        Assert.Equal("D-Bus System Message Bus", dbus.Description);
    }

    [Fact]
    public void ServiceScanner_ParseOutput_EmptyInput_YieldsNoServices()
    {
        var builder = new ScanDataBuilder();
        ServiceScanner.ParseOutput("", builder);
        var data = builder.Build();

        Assert.Empty(data.RunningServices);
    }

    [Fact]
    public void ServiceScanner_ParseOutput_ShortLine_IsSkipped()
    {
        var builder = new ScanDataBuilder();
        ServiceScanner.ParseOutput("sshd.service loaded active", builder);
        var data = builder.Build();

        Assert.Empty(data.RunningServices);
    }

    // =====================================================================
    // NetworkScanner Fixtures
    // =====================================================================

    private const string IpAddrSample = """
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
            link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
            inet 127.0.0.1/8 scope host lo
               valid_lft forever preferred_lft forever
            inet6 ::1/128 scope host
               valid_lft forever preferred_lft forever
        2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
            link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
            inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0
               valid_lft 86394sec preferred_lft 86394sec
            inet6 fe80::211:22ff:fe33:4455/64 scope link
               valid_lft forever preferred_lft forever
        3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
            link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
        """;

    private const string IpRouteSample = """
        default via 192.168.1.1 dev eth0 proto dhcp metric 100
        192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10 metric 100
        172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1
        """;

    private const string SsConnectionsSample = """
        Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port Process
        tcp    ESTAB   0       0       192.168.1.10:22    192.168.1.5:54321  users:(("sshd",pid=1234,fd=3))
        tcp    TIME-WAIT 0    0       192.168.1.10:8080  10.0.0.1:45678
        udp    ESTAB   0       0       192.168.1.10:53    8.8.8.8:53         users:(("systemd-resolve",pid=500,fd=12))
        """;

    [Fact]
    public void NetworkScanner_ParseAddresses_ExtractsInterfaces()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseAddresses(IpAddrSample, builder);
        var data = builder.Build();

        Assert.Equal(3, data.NetworkInterfaces.Count);

        var lo = data.NetworkInterfaces.First(i => i.Name == "lo");
        Assert.True(lo.IsUp);
        Assert.Contains("127.0.0.1/8", lo.Addresses);
        Assert.Contains("::1/128", lo.Addresses);

        var eth0 = data.NetworkInterfaces.First(i => i.Name == "eth0");
        Assert.True(eth0.IsUp);
        Assert.Equal("00:11:22:33:44:55", eth0.MacAddress);
        Assert.Contains("192.168.1.10/24", eth0.Addresses);
        Assert.Contains("fe80::211:22ff:fe33:4455/64", eth0.Addresses);

        var wlan0 = data.NetworkInterfaces.First(i => i.Name == "wlan0");
        // Interface is administratively UP even with NO-CARRIER
        Assert.True(wlan0.IsUp);
        Assert.Equal("aa:bb:cc:dd:ee:ff", wlan0.MacAddress);
    }

    [Fact]
    public void NetworkScanner_ParseAddresses_EmptyInput_YieldsNoInterfaces()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseAddresses("", builder);
        var data = builder.Build();

        Assert.Empty(data.NetworkInterfaces);
    }

    [Fact]
    public void NetworkScanner_ParseRoutes_ExtractsRoutes()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseRoutes(IpRouteSample, builder);
        var data = builder.Build();

        Assert.Equal(3, data.Routes.Count);

        var def = data.Routes.First(r => r.Destination == "default");
        Assert.Equal("192.168.1.1", def.Gateway);
        Assert.Equal("eth0", def.Interface);
        Assert.Equal("dhcp", def.Flags);

        var local = data.Routes.First(r => r.Destination == "192.168.1.0/24");
        Assert.Null(local.Gateway);
        Assert.Equal("eth0", local.Interface);
        Assert.Equal("kernel", local.Flags);

        var docker = data.Routes.First(r => r.Destination == "172.17.0.0/16");
        Assert.Equal("docker0", docker.Interface);
    }

    [Fact]
    public void NetworkScanner_ParseRoutes_EmptyInput_YieldsNoRoutes()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseRoutes("", builder);
        var data = builder.Build();

        Assert.Empty(data.Routes);
    }

    [Fact]
    public void NetworkScanner_ParseConnections_ExtractsConnections()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseConnections(SsConnectionsSample, builder);
        var data = builder.Build();

        Assert.Equal(3, data.ActiveConnections.Count);

        var ssh = data.ActiveConnections.First(c => c.LocalPort == 22);
        Assert.Equal("tcp", ssh.Protocol);
        Assert.Equal("ESTAB", ssh.State);
        Assert.Equal("192.168.1.10", ssh.LocalAddress);
        Assert.Equal("192.168.1.5", ssh.RemoteAddress);
        Assert.Equal(54321, ssh.RemotePort);
        Assert.Equal("sshd", ssh.ProcessName);

        var web = data.ActiveConnections.First(c => c.LocalPort == 8080);
        Assert.Equal("TIME-WAIT", web.State);
        Assert.Equal("10.0.0.1", web.RemoteAddress);
        Assert.Equal(45678, web.RemotePort);

        var dns = data.ActiveConnections.First(c => c.LocalPort == 53);
        Assert.Equal("udp", dns.Protocol);
        Assert.Equal("8.8.8.8", dns.RemoteAddress);
        Assert.Equal("systemd-resolve", dns.ProcessName);
    }

    [Fact]
    public void NetworkScanner_ParseConnections_EmptyInput_YieldsNoConnections()
    {
        var builder = new ScanDataBuilder();
        NetworkScanner.ParseConnections("", builder);
        var data = builder.Build();

        Assert.Empty(data.ActiveConnections);
    }

    [Fact]
    public void NetworkScanner_ParseAddressPort_Ipv4_ReturnsAddressAndPort()
    {
        var (addr, port) = NetworkScanner.ParseAddressPort("192.168.1.10:22");
        Assert.Equal("192.168.1.10", addr);
        Assert.Equal(22, port);
    }

    [Fact]
    public void NetworkScanner_ParseAddressPort_Ipv6_ReturnsAddressAndPort()
    {
        var (addr, port) = NetworkScanner.ParseAddressPort("[::1]:53");
        Assert.Equal("::1", addr);
        Assert.Equal(53, port);
    }

    // =====================================================================
    // Scanner Capability Tests
    // =====================================================================

    [Fact]
    public async Task FirewallScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new FirewallScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "iptables");
        Assert.Contains(data.Capabilities, c => c.SourceName == "nftables");
    }

    [Fact]
    public async Task PortScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new PortScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "ss");
        Assert.Contains(data.Capabilities, c => c.SourceName == "netstat");
    }

    [Fact]
    public async Task NetworkScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new NetworkScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "ip addr");
        Assert.Contains(data.Capabilities, c => c.SourceName == "ip route");
        Assert.Contains(data.Capabilities, c => c.SourceName == "ss connections");
    }

    [Fact]
    public async Task ServiceScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new ServiceScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "systemctl");
    }
}
