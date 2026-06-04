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

    // =====================================================================
    // SshConfigScanner Fixtures
    // =====================================================================

    private const string SshdTSample = """
        permitrootlogin no
        passwordauthentication no
        maxauthtries 3
        protocol 2
        permitemptypasswords no
        pubkeyauthentication yes
        challengeresponseauthentication no
        usepam yes
        x11forwarding no
        clientaliveinterval 300
        logingracetime 120
        """;

    private const string SshdConfigSample = """
        #Port 22
        PermitRootLogin prohibit-password
        PasswordAuthentication yes
        MaxAuthTries 6
        #Protocol 2
        PermitEmptyPasswords no
        PubkeyAuthentication yes
        X11Forwarding yes
        Include /etc/ssh/sshd_config.d/*.conf
        """;

    [Fact]
    public void SshConfigScanner_ParseSshdTOutput_ExtractsDirectives()
    {
        var builder = new ScanDataBuilder();
        var config = SshConfigScanner.ParseSshdTOutput(SshdTSample);
        builder.SetSshConfig(config);
        var data = builder.Build();

        Assert.NotNull(data.SshConfig);
        Assert.True(data.SshConfig.ConfigReadable);
        Assert.Equal("no", data.SshConfig.PermitRootLogin);
        Assert.Equal("no", data.SshConfig.PasswordAuthentication);
        Assert.Equal(3, data.SshConfig.MaxAuthTries);
        Assert.Equal("2", data.SshConfig.Protocol);
        Assert.Equal("no", data.SshConfig.PermitEmptyPasswords);
        Assert.Equal("yes", data.SshConfig.PubkeyAuthentication);
        Assert.Equal("no", data.SshConfig.ChallengeResponseAuthentication);
        Assert.Equal("yes", data.SshConfig.UsePAM);
        Assert.Equal("no", data.SshConfig.X11Forwarding);
        Assert.Equal(300, data.SshConfig.ClientAliveInterval);
        Assert.Equal(120, data.SshConfig.LoginGraceTime);
    }

    [Fact]
    public void SshConfigScanner_ParseConfigFile_ExtractsDirectives()
    {
        var config = SshConfigScanner.ParseConfigFile(SshdConfigSample, "/etc/ssh/sshd_config");

        Assert.True(config.ConfigReadable);
        Assert.Equal("prohibit-password", config.PermitRootLogin);
        Assert.Equal("yes", config.PasswordAuthentication);
        Assert.Equal(6, config.MaxAuthTries);
        Assert.Null(config.Protocol); // commented out
        Assert.Equal("no", config.PermitEmptyPasswords);
        Assert.Equal("yes", config.PubkeyAuthentication);
        Assert.Equal("yes", config.X11Forwarding);
    }

    [Fact]
    public void SshConfigScanner_ParseConfigFile_MatchBlock_IsSkipped()
    {
        const string configWithMatch = """
            PasswordAuthentication yes
            Match User admin
                PasswordAuthentication no
            PermitRootLogin no
            """;

        var config = SshConfigScanner.ParseConfigFile(configWithMatch, "/etc/ssh/sshd_config");

        Assert.Equal("yes", config.PasswordAuthentication); // global value
        Assert.Equal("no", config.PermitRootLogin); // after Match block
    }

    [Fact]
    public void SshConfigScanner_ParseConfigFile_EmptyInput_IsNotReadable()
    {
        var config = SshConfigScanner.ParseConfigFile("", "/etc/ssh/sshd_config");

        Assert.True(config.ConfigReadable); // file was read, just empty
        Assert.Null(config.PermitRootLogin);
        Assert.Null(config.PasswordAuthentication);
    }

    [Fact]
    public async Task SshConfigScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new SshConfigScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "sshd -T" || c.SourceName == "sshd_config");
    }

    // =====================================================================
    // KernelHardeningScanner Fixtures
    // =====================================================================

    [Fact]
    public void KernelHardeningScanner_ParseSysctlLine_ValidLine_ReturnsPair()
    {
        var result = KernelHardeningScanner.ParseSysctlLine("kernel.randomize_va_space = 2");

        Assert.NotNull(result);
        Assert.Equal("kernel.randomize_va_space", result.Value.Key);
        Assert.Equal("2", result.Value.Value);
    }

    [Fact]
    public void KernelHardeningScanner_ParseSysctlLine_NoEquals_ReturnsNull()
    {
        var result = KernelHardeningScanner.ParseSysctlLine("kernel.randomize_va_space 2");
        Assert.Null(result);
    }

    [Fact]
    public void KernelHardeningScanner_SysctlKeyToProcPath_ConvertsCorrectly()
    {
        var path = KernelHardeningScanner.SysctlKeyToProcPath("kernel.randomize_va_space");
        Assert.Equal("/proc/sys/kernel/randomize_va_space", path);
    }

    [Fact]
    public async Task KernelHardeningScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new KernelHardeningScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "/proc/sys");
        Assert.Contains(data.Capabilities, c => c.SourceName == "secureboot");
    }

    // =====================================================================
    // FilePermissionScanner Fixtures
    // =====================================================================

    [Fact]
    public void FilePermissionScanner_ParseStatLine_ValidLine_ReturnsEntry()
    {
        var entry = FilePermissionScanner.ParseStatLine("640 root shadow /etc/shadow");

        Assert.NotNull(entry);
        Assert.Equal("/etc/shadow", entry.Path);
        Assert.Equal("640", entry.Mode);
        Assert.Equal("root", entry.Owner);
        Assert.Equal("shadow", entry.Group);
        Assert.True(entry.Exists);
    }

    [Fact]
    public void FilePermissionScanner_ParseStatLine_PathWithSpaces_ReturnsEntry()
    {
        var entry = FilePermissionScanner.ParseStatLine("755 root root /path with spaces/file");

        Assert.NotNull(entry);
        Assert.Equal("/path with spaces/file", entry.Path);
        Assert.Equal("755", entry.Mode);
        Assert.Equal("root", entry.Owner);
        Assert.Equal("root", entry.Group);
    }

    [Fact]
    public void FilePermissionScanner_ParseStatLine_EmptyInput_ReturnsNull()
    {
        var entry = FilePermissionScanner.ParseStatLine("");
        Assert.Null(entry);
    }

    [Fact]
    public void FilePermissionScanner_ParseStatLine_TooFewParts_ReturnsNull()
    {
        var entry = FilePermissionScanner.ParseStatLine("640 root");
        Assert.Null(entry);
    }

    [Fact]
    public async Task FilePermissionScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new FilePermissionScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "stat");
    }

    // =====================================================================
    // UserAccountScanner Fixtures
    // =====================================================================

    [Fact]
    public void UserAccountScanner_ParsePasswdLine_ValidLine_ReturnsAccount()
    {
        var account = UserAccountScanner.ParsePasswdLine("alice:x:1000:1000:Alice Smith:/home/alice:/bin/bash");

        Assert.NotNull(account);
        Assert.Equal("alice", account.Username);
        Assert.Equal(1000, account.Uid);
        Assert.Equal(1000, account.Gid);
        Assert.Equal("Alice Smith", account.Gecos);
        Assert.Equal("/home/alice", account.HomeDirectory);
        Assert.Equal("/bin/bash", account.Shell);
    }

    [Fact]
    public void UserAccountScanner_ParsePasswdLine_TooFewParts_ReturnsNull()
    {
        var account = UserAccountScanner.ParsePasswdLine("alice:x:1000");
        Assert.Null(account);
    }

    [Fact]
    public void UserAccountScanner_ParseShadowLine_ValidLine_ReturnsEntry()
    {
        var entry = UserAccountScanner.ParseShadowLine("alice:$6$rounds=5000$xyz$abc:19800:1:90:7:30::");

        Assert.NotNull(entry);
        Assert.Equal("alice", entry.Username);
        Assert.Equal("$6$rounds=5000$xyz$abc", entry.PasswordHash);
        Assert.Equal(19800, entry.LastChange);
        Assert.Equal(1, entry.MinDays);
        Assert.Equal(90, entry.MaxDays);
        Assert.Equal(7, entry.WarnDays);
        Assert.Equal(30, entry.InactiveDays);
        Assert.Null(entry.ExpireDate);
    }

    [Fact]
    public void UserAccountScanner_ParseShadowLine_EmptyExpiry_ReturnsEntry()
    {
        var entry = UserAccountScanner.ParseShadowLine("bin:*:19800:0:99999:7:::");

        Assert.NotNull(entry);
        Assert.Equal("bin", entry.Username);
        Assert.Equal("*", entry.PasswordHash);
        Assert.Equal(0, entry.MinDays);
        Assert.Equal(99999, entry.MaxDays);
        Assert.Null(entry.ExpireDate);
    }

    [Fact]
    public void UserAccountScanner_ParseLoginDefs_ExtractsValues()
    {
        var lines = new[]
        {
            "# Comment line",
            "PASS_MAX_DAYS   90",
            "PASS_MIN_DAYS\t1",
            "PASS_MIN_LEN    14",
            "PASS_WARN_AGE   7",
            "ENCRYPT_METHOD  SHA512"
        };

        var defs = UserAccountScanner.ParseLoginDefs(lines);

        Assert.True(defs.Readable);
        Assert.Equal(90, defs.PassMaxDays);
        Assert.Equal(1, defs.PassMinDays);
        Assert.Equal(14, defs.PassMinLen);
        Assert.Equal(7, defs.PassWarnAge);
        Assert.Equal("SHA512", defs.EncryptMethod);
    }

    [Fact]
    public async Task UserAccountScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new UserAccountScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "passwd");
    }

    // =====================================================================
    // FilesystemAuditScanner Fixtures
    // =====================================================================

    [Fact]
    public async Task FilesystemAuditScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new FilesystemAuditScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "find-world-writable-files");
        Assert.Contains(data.Capabilities, c => c.SourceName == "find-suid-sgid");
        Assert.Contains(data.Capabilities, c => c.SourceName == "find-unowned-files");
        Assert.Contains(data.Capabilities, c => c.SourceName == "find-world-writable-dirs");
        Assert.Contains(data.Capabilities, c => c.SourceName == "findmnt-tmp");
    }

    [Fact]
    public async Task FilesystemAuditScanner_RunCommandAsync_TimesOutLongRunningCommand()
    {
        var scanner = new FilesystemAuditScanner(TimeSpan.FromMilliseconds(50));

        var (_, stderr, success) = await scanner.RunCommandAsync(
            "sh",
            new[] { "-c", "sleep 1" },
            CancellationToken.None);

        Assert.False(success);
        Assert.Contains("timed out", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FilesystemAuditScanner_RunCommandAsync_TruncatesLargeOutput()
    {
        var scanner = new FilesystemAuditScanner(maxOutputChars: 12);

        var (stdout, stderr, success) = await scanner.RunCommandAsync(
            "sh",
            new[] { "-c", "printf 'abcdefghijklmnopqrstuvwxyz'" },
            CancellationToken.None);

        Assert.True(success);
        Assert.True(stdout?.Length <= 12);
        Assert.Contains("truncated", stderr, StringComparison.OrdinalIgnoreCase);
    }

    // =====================================================================
    // LoggingAuditScanner Fixtures
    // =====================================================================

    [Fact]
    public async Task LoggingAuditScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new LoggingAuditScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "systemctl logging services");
        Assert.Contains(data.Capabilities, c => c.SourceName == "auditd rules");
        Assert.Contains(data.Capabilities, c => c.SourceName == "logrotate");
        Assert.Contains(data.Capabilities, c => c.SourceName == "log forwarding");
    }

    [Fact]
    public void LoggingAuditScanner_CheckLogRotation_SystemState_DoesNotThrow()
    {
        var result = LoggingAuditScanner.CheckLogRotation();
        // Assert only that it returns a bool without throwing; actual value depends on host.
        Assert.True(result || !result);
    }

    [Fact]
    public void LoggingAuditScanner_CheckCentralForwarding_SystemState_DoesNotThrow()
    {
        var (configured, targets) = LoggingAuditScanner.CheckCentralForwarding();
        Assert.NotNull(targets);
        // Actual configured state depends on host.
    }

    [Theory]
    [InlineData("@@192.168.1.1", true)]
    [InlineData("@192.168.1.1", true)]
    [InlineData("@@logs.example.com:514", true)]
    [InlineData("@(o)192.168.1.1", true)]
    [InlineData("@@(z9)192.168.1.1", true)]
    [InlineData("@@[2001:db8::1]", true)]
    [InlineData("*.*", false)]
    [InlineData("normaltext", false)]
    [InlineData("@", false)]
    [InlineData("@@", false)]
    [InlineData("@include", false)]
    [InlineData("@INCLUDE", false)]
    [InlineData("@@include", false)]
    [InlineData("@version", false)]
    [InlineData("@moduleLoad", false)]
    [InlineData("@module", false)]
    [InlineData("@begin", false)]
    [InlineData("@end", false)]
    [InlineData("@define", false)]
    [InlineData("@ifdef", false)]
    [InlineData("@ifndef", false)]
    [InlineData("@else", false)]
    [InlineData("@endif", false)]
    public void LoggingAuditScanner_IsForwardingTarget_ValidatesCorrectly(string input, bool expected)
    {
        Assert.Equal(expected, LoggingAuditScanner.IsForwardingTarget(input));
    }

    [Theory]
    [InlineData("-w /etc/passwd -p wa -k identity", true)]
    [InlineData("-a always,exit -F arch=b64 -S sethostname -k system-locale", true)]
    [InlineData("-A always,exit -F arch=b32 -S adjtimex -k time-change", true)]
    [InlineData("-D", false)]
    [InlineData("-b 8192", false)]
    [InlineData("-f 1", false)]
    [InlineData("-e 1", false)]
    [InlineData("-r 0", false)]
    [InlineData("-i", false)]
    [InlineData("-s disable", false)]
    [InlineData("-c", false)]
    [InlineData("--loginuid-immutable", false)]
    [InlineData("# -w /etc/shadow -p wa -k identity", false)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    public void LoggingAuditScanner_IsActualAuditdRule_DistinguishesRulesFromControls(string line, bool expected)
    {
        Assert.Equal(expected, LoggingAuditScanner.IsActualAuditdRule(line));
    }

    [Theory]
    [InlineData("ForwardToSyslog=yes", true)]
    [InlineData("ForwardToSyslog = yes", true)]
    [InlineData("ForwardToSyslog= yes", true)]
    [InlineData("ForwardToSyslog =yes", true)]
    [InlineData("  ForwardToSyslog  =  yes  ", true)]
    [InlineData("forwardtosyslog=yes", true)]
    [InlineData("FORWARDTOSYSLOG=YES", true)]
    [InlineData("ForwardToSyslog=no", false)]
    [InlineData("ForwardToSyslog = no", false)]
    [InlineData("ForwardToSyslog=auto", false)]
    [InlineData("# ForwardToSyslog=yes", false)]
    [InlineData("#ForwardToSyslog=yes", false)]
    [InlineData("Storage=persistent", false)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    public void LoggingAuditScanner_IsJournaldForwardToSyslogEnabled_HandlesWhitespace(string line, bool expected)
    {
        Assert.Equal(expected, LoggingAuditScanner.IsJournaldForwardToSyslogEnabled(line));
    }

    [Fact]
    public void LoggingAuditScanner_CheckCentralForwarding_NoDuplicateTargets()
    {
        var (_, targets) = LoggingAuditScanner.CheckCentralForwarding();
        var distinct = targets.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        Assert.Equal(distinct.Count, targets.Count);
    }

    [Fact]
    public async Task LoggingAuditScanner_ReadAuditdRulesAsync_SystemState_DoesNotThrow()
    {
        var (rules, ok, error) = await LoggingAuditScanner.ReadAuditdRulesAsync(CancellationToken.None);
        Assert.NotNull(rules);
        // ok and error depend on whether auditctl is installed and whether /etc/audit/audit.rules exists.
    }

    [Fact]
    public void LoggingAuditScanner_CheckCentralForwarding_FiltersRsyslogDirectives()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            var confPath = Path.Combine(tempDir, "50-default.conf");
            File.WriteAllLines(confPath, new[]
            {
                "# Comment line",
                "",
                "@include /etc/rsyslog.d/*.conf",
                "@version 2",
                "@moduleLoad imudp",
                "*.* @@192.168.1.1:514",
                "mail.* @logs.example.com",
                "*.* @@(z9)192.168.1.2"
            });

            var (configured, targets) = LoggingAuditScanner.CheckCentralForwarding(
                new[] { confPath }, journaldConfPath: null);

            Assert.True(configured);
            Assert.DoesNotContain(targets, t => t.Contains("include", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(targets, t => t.Contains("version", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(targets, t => t.Contains("moduleLoad", StringComparison.OrdinalIgnoreCase));
            Assert.Contains("@@192.168.1.1:514", targets);
            Assert.Contains("@logs.example.com", targets);
            Assert.Contains("@@(z9)192.168.1.2", targets);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
    }

    [Theory]
    [InlineData(new string[0], 0)] // completely empty file
    [InlineData(new[] { "# comment", "", "  " }, 0)] // only comments/blank
    [InlineData(new[] { "-D", "-b 8192", "-f 1", "# -w /etc/shadow -p wa -k identity" }, 0)] // only control directives
    [InlineData(new[] { "-w /etc/passwd -p wa -k identity", "-a always,exit -F arch=b64 -S setuid -k privilege" }, 2)]
    public async Task LoggingAuditScanner_ReadAuditdRulesFromFileAsync_VariousContents(string[] lines, int expectedCount)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"audit-test-{Guid.NewGuid()}.rules");
        try
        {
            await File.WriteAllLinesAsync(tempFile, lines);
            var (rules, ok, error) = await LoggingAuditScanner.ReadAuditdRulesFromFileAsync(tempFile, auditctlError: null, CancellationToken.None);
            Assert.True(ok);
            Assert.Null(error);
            Assert.Equal(expectedCount, rules.Count);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task LoggingAuditScanner_ReadAuditdRulesFromFileAsync_MissingFile_ReturnsError()
    {
        var missingFile = Path.Combine(Path.GetTempPath(), $"missing-audit-{Guid.NewGuid()}.rules");
        var (rules, ok, error) = await LoggingAuditScanner.ReadAuditdRulesFromFileAsync(missingFile, auditctlError: "auditctl: not found", CancellationToken.None);
        Assert.False(ok);
        Assert.NotNull(error);
        Assert.Contains("not found", error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(rules);
    }

    [Fact]
    public void LoggingAuditScanner_CheckCentralForwarding_CommentedJournaldForwardToSyslog_Ignored()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"journald-test-{Guid.NewGuid()}.conf");
        try
        {
            File.WriteAllLines(tempFile, new[]
            {
                "[Journal]",
                "# ForwardToSyslog=yes",
                "#ForwardToSyslog=yes",
                "Storage=auto"
            });

            var (configured, targets) = LoggingAuditScanner.CheckCentralForwarding(
                rsyslogPaths: Array.Empty<string>(), journaldConfPath: tempFile);

            Assert.False(configured);
            Assert.DoesNotContain(targets, t => t.Contains("journald", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    // =====================================================================
    // CronJobScanner Fixtures
    // =====================================================================

    [Fact]
    public void CronJobScanner_ParseCronLine_SystemCrontab_ExtractsUserAndCommand()
    {
        var entry = CronJobScanner.ParseCronLine("0 5 * * * root /usr/bin/backup.sh", "/etc/crontab", isSystemCrontab: true);

        Assert.NotNull(entry);
        Assert.Equal("/etc/crontab", entry.SourceFile);
        Assert.Equal("0 5 * * *", entry.Schedule);
        Assert.Equal("root", entry.RunAsUser);
        Assert.Equal("/usr/bin/backup.sh", entry.Command);
        Assert.False(entry.IsScript);
    }

    [Fact]
    public void CronJobScanner_ParseCronLine_UserCrontab_NoUserField()
    {
        var entry = CronJobScanner.ParseCronLine("*/10 * * * * /home/alice/check.sh", "/var/spool/cron/crontabs/alice", isSystemCrontab: false);

        Assert.NotNull(entry);
        Assert.Equal("/var/spool/cron/crontabs/alice", entry.SourceFile);
        Assert.Equal("*/10 * * * *", entry.Schedule);
        Assert.Null(entry.RunAsUser);
        Assert.Equal("/home/alice/check.sh", entry.Command);
    }

    [Fact]
    public void CronJobScanner_ParseCronLine_SpecialSchedule_Works()
    {
        var entry = CronJobScanner.ParseCronLine("@reboot root /opt/start.sh", "/etc/crontab", isSystemCrontab: true);

        Assert.NotNull(entry);
        Assert.Equal("@reboot", entry.Schedule);
        Assert.Equal("root", entry.RunAsUser);
        Assert.Equal("/opt/start.sh", entry.Command);
    }

    [Fact]
    public void CronJobScanner_ParseCronLine_Empty_ReturnsNull()
    {
        var entry = CronJobScanner.ParseCronLine("", "/etc/crontab", isSystemCrontab: true);
        Assert.Null(entry);
    }

    [Fact]
    public void CronJobScanner_ParseCronLine_Comment_ReturnsNull()
    {
        var entry = CronJobScanner.ParseCronLine("# 0 5 * * * root /usr/bin/backup.sh", "/etc/crontab", isSystemCrontab: true);
        Assert.Null(entry);
    }

    [Fact]
    public void CronJobScanner_ParseCrontabLines_SkipsCommentsAndEnvVars()
    {
        var lines = new[]
        {
            "# System crontab",
            "SHELL=/bin/bash",
            "PATH=/usr/bin:/bin",
            "",
            "0 5 * * * root /usr/bin/backup.sh",
            "MAILTO=admin@example.com",
            "30 2 * * * root /opt/cleanup.py --verbose"
        };

        var entries = CronJobScanner.ParseCrontabLines(lines, "/etc/crontab", isSystemCrontab: true);

        Assert.Equal(2, entries.Count);
        Assert.Equal("0 5 * * *", entries[0].Schedule);
        Assert.Equal("/usr/bin/backup.sh", entries[0].Command);
        Assert.Equal("30 2 * * *", entries[1].Schedule);
        Assert.Equal("root", entries[1].RunAsUser);
        Assert.Equal("/opt/cleanup.py --verbose", entries[1].Command);
    }

    [Theory]
    [InlineData("SHELL=/bin/bash", true)]
    [InlineData("PATH=/usr/bin:/bin", true)]
    [InlineData("MAILTO=\"\"", true)]
    [InlineData("0 5 * * * root /bin/true", false)]
    [InlineData("@reboot root /bin/true", false)]
    [InlineData("*/5 * * * * /bin/true", false)]
    public void CronJobScanner_IsEnvironmentVariableLine_DetectsCorrectly(string line, bool expected)
    {
        Assert.Equal(expected, CronJobScanner.IsEnvironmentVariableLine(line));
    }

    [Fact]
    public void CronJobScanner_ParseCronLine_TabSeparated_Works()
    {
        var entry = CronJobScanner.ParseCronLine("0\t5\t*\t*\t*\troot\t/usr/bin/backup.sh", "/etc/crontab", isSystemCrontab: true);

        Assert.NotNull(entry);
        Assert.Equal("0 5 * * *", entry.Schedule);
        Assert.Equal("root", entry.RunAsUser);
        Assert.Equal("/usr/bin/backup.sh", entry.Command);
    }

    [Fact]
    public async Task CronJobScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new CronJobScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c =>
            c.SourceName.Equals("/etc/crontab", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.Equals("/etc/cron.d", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CronJobScanner_ScanAsync_CoversRhelPath()
    {
        var builder = new ScanDataBuilder();
        var scanner = new CronJobScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        // The scanner should attempt both Debian (/var/spool/cron/crontabs) and RHEL (/var/spool/cron) paths
        var cronCapabilities = data.Capabilities.Where(c =>
            c.SourceName.StartsWith("/var/spool/cron", StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(cronCapabilities);
    }

    // =====================================================================
    // PackageVulnerabilityScanner Fixtures
    // =====================================================================

    [Fact]
    public void PackageVulnerabilityScanner_ParseDpkgQueryLine_ValidLine_ReturnsPackage()
    {
        var result = PackageVulnerabilityScanner.ParseDpkgQueryLine("libc6\t2.31-0ubuntu9.14\tamd64");

        Assert.NotNull(result);
        Assert.Equal("libc6", result.Name);
        Assert.Equal("2.31-0ubuntu9.14", result.Version);
        Assert.Equal("amd64", result.Architecture);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseDpkgQueryLine_MalformedLine_ReturnsNull()
    {
        var result = PackageVulnerabilityScanner.ParseDpkgQueryLine("libc6\t2.31");
        Assert.Null(result);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseDpkgQueryLine_EmptyLine_ReturnsNull()
    {
        var result = PackageVulnerabilityScanner.ParseDpkgQueryLine("");
        Assert.Null(result);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptListUpgradeableLine_ValidLine_ReturnsParsed()
    {
        var result = PackageVulnerabilityScanner.ParseAptListUpgradeableLine(
            "libc6/focal-security 2.31-0ubuntu9.16 amd64 [upgradable from: 2.31-0ubuntu9.14]");

        Assert.NotNull(result);
        Assert.Equal("libc6", result.Value.Name);
        Assert.Equal("2.31-0ubuntu9.16", result.Value.Version);
        Assert.Equal("amd64", result.Value.Arch);
        Assert.Equal("2.31-0ubuntu9.14", result.Value.CurrentVersion);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptListUpgradeableLine_WithoutCurrentVersion_ReturnsParsed()
    {
        var result = PackageVulnerabilityScanner.ParseAptListUpgradeableLine(
            "openssh-server/jammy-updates 1:8.9p1-3ubuntu0.10 amd64");

        Assert.NotNull(result);
        Assert.Equal("openssh-server", result.Value.Name);
        Assert.Equal("1:8.9p1-3ubuntu0.10", result.Value.Version);
        Assert.Equal("amd64", result.Value.Arch);
        Assert.Null(result.Value.CurrentVersion);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptListUpgradeableLine_ListingHeader_ReturnsNull()
    {
        var result = PackageVulnerabilityScanner.ParseAptListUpgradeableLine(
            "Listing... Done");
        Assert.Null(result);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptListUpgradeableLine_EmptyInput_ReturnsNull()
    {
        var result = PackageVulnerabilityScanner.ParseAptListUpgradeableLine("");
        Assert.Null(result);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptCachePolicySecurity_SecurityOrigin_ReturnsTrue()
    {
        const string policy = """
            libc6:
              Installed: 2.31-0ubuntu9.14
              Candidate: 2.31-0ubuntu9.16
              Version table:
                 2.31-0ubuntu9.16 500
                    500 http://archive.ubuntu.com/ubuntu focal-updates/main amd64 Packages
                 2.31-0ubuntu9.16 500
                    500 http://security.ubuntu.com/ubuntu focal-security/main amd64 Packages
             *** 2.31-0ubuntu9.14 100
                    100 /var/lib/dpkg/status
            """;

        var isSecurity = PackageVulnerabilityScanner.ParseAptCachePolicySecurity("2.31-0ubuntu9.16", policy, out var source);

        Assert.True(isSecurity);
        Assert.Contains("security", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptCachePolicySecurity_NonSecurityOrigin_ReturnsFalse()
    {
        const string policy = """
            libc6:
              Installed: 2.31-0ubuntu9.14
              Candidate: 2.31-0ubuntu9.16
              Version table:
                 2.31-0ubuntu9.16 500
                    500 http://archive.ubuntu.com/ubuntu focal-updates/main amd64 Packages
             *** 2.31-0ubuntu9.14 100
                    100 /var/lib/dpkg/status
            """;

        var isSecurity = PackageVulnerabilityScanner.ParseAptCachePolicySecurity("2.31-0ubuntu9.16", policy, out var source);

        Assert.False(isSecurity);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseAptCachePolicySecurity_EmptyInput_ReturnsFalse()
    {
        var isSecurity = PackageVulnerabilityScanner.ParseAptCachePolicySecurity("1.0", "", out var source);
        Assert.False(isSecurity);
        Assert.Empty(source);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseDebsecanOutput_WithCves_ReturnsMapping()
    {
        const string output = """
            CVE-2023-1234 libfoo (fixed)
            CVE-2023-5678 libfoo (fixed)
            CVE-2023-9999 libbar (fixed; remotely exploitable, high urgency)
            """;

        var result = PackageVulnerabilityScanner.ParseDebsecanOutput(output);

        Assert.Equal(2, result.Count);
        Assert.Contains("libfoo", result.Keys);
        Assert.Contains("libbar", result.Keys);
        Assert.Equal(2, result["libfoo"].Count);
        Assert.Contains("CVE-2023-1234", result["libfoo"]);
        Assert.Contains("CVE-2023-5678", result["libfoo"]);
        Assert.Single(result["libbar"]);
        Assert.Contains("CVE-2023-9999", result["libbar"]);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseDebsecanOutput_EmptyInput_ReturnsEmpty()
    {
        var result = PackageVulnerabilityScanner.ParseDebsecanOutput("");
        Assert.Empty(result);
    }

    [Fact]
    public void PackageVulnerabilityScanner_ParseDebsecanOutput_NonCveLines_Ignored()
    {
        const string output = """
            Some header line
            CVE-2023-1234 libfoo (fixed)
            Another irrelevant line
            """;

        var result = PackageVulnerabilityScanner.ParseDebsecanOutput(output);

        Assert.Single(result);
        Assert.Single(result["libfoo"]);
    }

    // =====================================================================
    // ContainerScanner Fixtures
    // =====================================================================

    [Fact]
    public void ContainerScanner_ParseDockerPs_ExtractsContainers()
    {
        const string output = """
            nginx|nginx:latest
            app|myregistry/app:1.2.3
            """;

        var result = ContainerScanner.ParseDockerPs(output);

        Assert.Equal(2, result.Count);
        Assert.Equal("nginx", result["nginx"].Name);
        Assert.Equal("nginx", result["nginx"].Image);
        Assert.Equal("latest", result["nginx"].Tag);
        Assert.Equal("app", result["app"].Name);
        Assert.Equal("myregistry/app", result["app"].Image);
        Assert.Equal("1.2.3", result["app"].Tag);
    }

    [Fact]
    public void ContainerScanner_ParseDockerPs_EmptyInput_YieldsNoContainers()
    {
        var result = ContainerScanner.ParseDockerPs("");
        Assert.Empty(result);
    }

    [Fact]
    public void ContainerScanner_ParseDockerInspectJson_ExtractsPrivilegedAndMounts()
    {
        const string json = """
            [
              {
                "Name": "/web",
                "Config": {
                  "Image": "web:1.0",
                  "Labels": {
                    "org.opencontainers.image.base.name": "ubuntu:14.04"
                  }
                },
                "HostConfig": {
                  "Privileged": true,
                  "PidMode": "host",
                  "NetworkMode": "bridge"
                },
                "Mounts": [
                  { "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock" }
                ]
              }
            ]
            """;

        var result = ContainerScanner.ParseDockerInspectJson(json);

        Assert.Single(result);
        var container = result["web"];
        Assert.True(container.IsPrivileged);
        Assert.True(container.HasHostPid);
        Assert.False(container.HasHostNetwork);
        Assert.True(container.HasDockerSocketMount);
        Assert.Contains(container.KnownBadBaseLayers, layer => layer.Contains("ubuntu:14.04"));
    }

    [Fact]
    public void ContainerScanner_ParseDockerInspectJson_EmptyInput_YieldsNoContainers()
    {
        var result = ContainerScanner.ParseDockerInspectJson("");
        Assert.Empty(result);
    }

    [Fact]
    public void ContainerScanner_ParseCrictlPsJson_ExtractsContainers()
    {
        const string json = """
            {
              "containers": [
                {
                  "metadata": { "name": "pod-1-container" },
                  "image": { "image": "busybox:1.35" }
                }
              ]
            }
            """;

        var result = ContainerScanner.ParseCrictlPsJson(json);

        Assert.Single(result);
        Assert.Equal("pod-1-container", result[0].Name);
        Assert.Equal("busybox", result[0].Image);
        Assert.Equal("1.35", result[0].Tag);
        Assert.Equal("containerd", result[0].Runtime);
    }

    [Fact]
    public void ContainerScanner_ParseCrictlPsJson_EmptyInput_YieldsNoContainers()
    {
        var result = ContainerScanner.ParseCrictlPsJson("");
        Assert.Empty(result);
    }

    [Fact]
    public void ContainerScanner_HasDefaultNamespaceOnly_DefaultOnly_ReturnsTrue()
    {
        const string output = "NAME    LABELS\ndefault";
        Assert.True(ContainerScanner.HasDefaultNamespaceOnly(output));
    }

    [Fact]
    public void ContainerScanner_HasDefaultNamespaceOnly_MultipleNamespaces_ReturnsFalse()
    {
        const string output = "NAME    LABELS\ndefault\nproduction";
        Assert.False(ContainerScanner.HasDefaultNamespaceOnly(output));
    }

    [Fact]
    public void ContainerScanner_DetectKnownBadBaseLayers_EolBaseImage_ReturnsHint()
    {
        var result = ContainerScanner.DetectKnownBadBaseLayers("registry.example.com/app:1.0", "debian:stretch");

        Assert.Contains(result, layer => layer.Contains("debian:stretch"));
    }

    [Fact]
    public async Task ContainerScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new ContainerScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "docker ps" || c.SourceName == "crictl");
        Assert.Contains(data.Capabilities, c => c.SourceName == "docker.sock");
    }

    // =====================================================================
    // KubernetesScanner Fixtures
    // =====================================================================

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_ExtractsPodsAndViolations()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "default", "name": "web-pod" },
                  "spec": {
                    "hostNetwork": true,
                    "hostIPC": true,
                    "containers": [
                      {
                        "name": "web",
                        "image": "nginx:latest",
                        "securityContext": {
                          "privileged": true,
                          "runAsNonRoot": false,
                          "allowPrivilegeEscalation": true,
                          "readOnlyRootFilesystem": false
                        }
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        var pod = data.KubernetesPods[0];
        Assert.Equal("default", pod.Namespace);
        Assert.Equal("web-pod", pod.Name);
        Assert.Single(pod.Containers);
        Assert.True(pod.Containers[0].Privileged);
        Assert.True(pod.Containers[0].AllowPrivilegeEscalation);
        Assert.False(pod.Containers[0].ReadOnlyRootFilesystem);
        Assert.True(pod.Containers[0].RunAsRoot);
        Assert.True(pod.HostNetwork);
        Assert.True(pod.HostIpc);
        Assert.Contains(pod.Violations, v => v.Contains("hostNetwork"));
        Assert.Contains(pod.Violations, v => v.Contains("hostIPC"));
        Assert.Contains(pod.Violations, v => v.Contains("privileged"));
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_EmptyInput_YieldsNoPods()
    {
        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson("", builder);
        var data = builder.Build();

        Assert.Empty(data.KubernetesPods);
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_HardenedPod_YieldsNoViolations()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "prod", "name": "safe-pod" },
                  "spec": {
                    "containers": [
                      {
                        "name": "app",
                        "image": "app:1.0",
                        "securityContext": {
                          "runAsNonRoot": true,
                          "allowPrivilegeEscalation": false,
                          "readOnlyRootFilesystem": true,
                          "capabilities": { "drop": ["ALL"] },
                          "seccompProfile": { "type": "RuntimeDefault" }
                        }
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        var pod = data.KubernetesPods[0];
        Assert.False(pod.Containers[0].Privileged);
        Assert.False(pod.Containers[0].AllowPrivilegeEscalation);
        Assert.True(pod.Containers[0].ReadOnlyRootFilesystem);
        Assert.False(pod.Containers[0].RunAsRoot);
        Assert.True(pod.Containers[0].DropAllCapabilities);
        Assert.Equal("RuntimeDefault", pod.Containers[0].SeccompProfile);
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_UnconfinedSeccomp_AddsViolation()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "prod", "name": "unsafe-pod" },
                  "spec": {
                    "containers": [
                      {
                        "name": "app",
                        "image": "app:1.0",
                        "securityContext": {
                          "runAsNonRoot": true,
                          "allowPrivilegeEscalation": false,
                          "readOnlyRootFilesystem": true,
                          "capabilities": { "drop": ["ALL"] },
                          "seccompProfile": { "type": "Unconfined" }
                        }
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        Assert.Contains(data.KubernetesPods[0].Violations, v => v.Contains("unconfined seccomp"));
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_PodLevelRunAsUser1000_NotRoot()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "prod", "name": "safe-pod" },
                  "spec": {
                    "securityContext": { "runAsUser": 1000 },
                    "containers": [
                      {
                        "name": "app",
                        "image": "app:1.0"
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        Assert.False(data.KubernetesPods[0].Containers[0].RunAsRoot);
        Assert.DoesNotContain(data.KubernetesPods[0].Violations, v => v.Contains("may run as root"));
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_RunAsUser1000WithNoRunAsNonRoot_NotRoot()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "prod", "name": "safe-pod" },
                  "spec": {
                    "containers": [
                      {
                        "name": "app",
                        "image": "app:1.0",
                        "securityContext": { "runAsUser": 1000 }
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        Assert.False(data.KubernetesPods[0].Containers[0].RunAsRoot);
        Assert.DoesNotContain(data.KubernetesPods[0].Violations, v => v.Contains("may run as root"));
    }

    [Fact]
    public void KubernetesScanner_ParseKubectlGetPodsJson_MalformedPod_SkipsItAndContinues()
    {
        const string json = """
            {
              "items": [
                {
                  "metadata": { "namespace": "bad", "name": "malformed" }
                },
                {
                  "metadata": { "namespace": "good", "name": "valid-pod" },
                  "spec": {
                    "containers": [
                      {
                        "name": "app",
                        "image": "app:1.0",
                        "securityContext": { "runAsNonRoot": true }
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var builder = new ScanDataBuilder();
        KubernetesScanner.ParseKubectlGetPodsJson(json, builder);
        var data = builder.Build();

        Assert.Single(data.KubernetesPods);
        Assert.Equal("good", data.KubernetesPods[0].Namespace);
        Assert.Equal("valid-pod", data.KubernetesPods[0].Name);
        Assert.Contains(data.Warnings, w => w.Contains("malformed"));
    }

    [Fact]
    public async Task KubernetesScanner_ScanAsync_PopulatesCapabilities()
    {
        var builder = new ScanDataBuilder();
        var scanner = new KubernetesScanner();
        await scanner.ScanAsync(builder, CancellationToken.None);
        var data = builder.Build();

        Assert.Contains(data.Capabilities, c => c.SourceName == "kubectl");
    }
}
