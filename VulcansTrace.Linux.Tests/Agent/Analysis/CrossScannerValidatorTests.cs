using System.Globalization;
using VulcansTrace.Linux.Agent.Analysis;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Analysis;

public class CrossScannerValidatorTests
{
    private readonly CrossScannerValidator _validator = new();

    [Fact]
    public void Validate_IgnoresInfoFindings()
    {
        var findings = new[]
        {
            CreateFinding("PORT-004", Severity.Info, "port 9999")
        };

        var scanData = CreateScanData();
        var result = _validator.Validate(findings, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_IgnoresMediumFindings_InPhase1()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: false,
            firewallRules: Array.Empty<FirewallRule>());

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_SupportsFw002_WhenSshListeningAndPublicInterfaceUp()
    {
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.Low);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } },
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsFw002_WhenPort22NotListening()
    {
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.Low);
        var scanData = CreateScanData(
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_ContradictsFw002_WhenOnlyLoopbackInterface()
    {
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.Low);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } },
            networkInterfaces: new[] { new NetworkInterface { Name = "lo", IsUp = true, Addresses = new[] { "127.0.0.1" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_DoesNotValidateFw002_MediumBranch()
    {
        // FW-002's Medium branch ("no explicit SSH rule") is not validated by design.
        var finding = CreateFinding("FW-002", Severity.Medium, "SSH/22", DetectionConfidence.Low);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } },
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_DoesNotValidate_WhenCapabilityPermissionLimited()
    {
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.Low);
        var scanData = CreateScanData(
            capabilities: new[]
            {
                new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.PermissionLimited },
                new DataSourceCapability { SourceName = "ip addr", Status = CapabilityStatus.Available }
            },
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_SupportsPort003_WhenNoFirewall()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "0.0.0.0:3306", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: false,
            firewallRules: Array.Empty<FirewallRule>());

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_SupportsPort003_WhenFirewallAcceptsPort()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "0.0.0.0:3306", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "ACCEPT",
                    DestinationPort = "3306",
                    RawLine = "ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:3306"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsPort003_WhenFirewallBlocksPort()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "0.0.0.0:3306", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "DROP",
                    DestinationPort = "3306",
                    RawLine = "DROP tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:3306"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_SupportsSsh002_WhenServiceAndPortConfirmed()
    {
        var finding = CreateFinding("SSH-002", Severity.High, "sshd", DetectionConfidence.Low);
        var scanData = CreateScanData(
            runningServices: new[] { new RunningService { Name = "ssh.service", State = "active/running" } },
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsSsh002_WhenSshNotReachable()
    {
        var finding = CreateFinding("SSH-002", Severity.High, "sshd", DetectionConfidence.Low);
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_SupportsSrv001_WhenTelnetPortListening()
    {
        var finding = CreateFinding("SRV-001", Severity.Critical, "telnet.socket", DetectionConfidence.Low);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 23, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsSrv001_WhenTelnetPortNotListening()
    {
        var finding = CreateFinding("SRV-001", Severity.Critical, "telnet.socket", DetectionConfidence.Low);
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_SupportsUser001_WhenSshReachable()
    {
        var finding = CreateFinding("USER-001", Severity.Critical, "admin (UID 0)", DetectionConfidence.Low);
        var scanData = CreateScanData(
            runningServices: new[] { new RunningService { Name = "ssh.service", State = "active/running" } },
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);

    }

    [Fact]
    public void Validate_DoesNotSupportUser001_WhenOnlySshServiceIsRunning()
    {
        var finding = CreateFinding("USER-001", Severity.Critical, "admin (UID 0)", DetectionConfidence.Low);
        var scanData = CreateScanData(
            runningServices: new[] { new RunningService { Name = "ssh.service", State = "active/running" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_DoesNotValidateUser001_WhenSshNotReachable()
    {
        var finding = CreateFinding("USER-001", Severity.Critical, "admin (UID 0)", DetectionConfidence.Low);
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_DoesNotValidatePort003_WhenFirewallSourceUnavailable()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "0.0.0.0:3306", DetectionConfidence.Low);
        var scanData = CreateScanData(
            capabilities: new[]
            {
                new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Available },
                new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Unavailable },
                new DataSourceCapability { SourceName = "nftables", Status = CapabilityStatus.Unavailable }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_CapsConfidenceAtHigh()
    {
        // Production findings currently start at Low, but this test documents the capping behavior.
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.High);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } },
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.High, validated.Confidence);
    }

    [Fact]
    public void Validate_KeepsConfirmedConfidence()
    {
        // Production findings currently start at Low, but this test documents that Confirmed is never downgraded.
        var finding = CreateFinding("FW-002", Severity.High, "SSH/22", DetectionConfidence.Confirmed);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } },
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Confirmed, validated.Confidence);
    }

    [Fact]
    public void Validate_LowersConfirmedConfidence_WhenContradicted()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "0.0.0.0:3306", DetectionConfidence.Confirmed);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "DROP",
                    DestinationPort = "3306",
                    RawLine = "DROP tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:3306"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.High, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_OnlyBumpsOnce_WhenSinglePredicateMatches()
    {
        // SSH-002's predicate considers two independent data sources but returns a single
        // support signal; confidence must bump only one level.
        var finding = CreateFinding("SSH-002", Severity.High, "sshd", DetectionConfidence.Low);
        var scanData = CreateScanData(
            runningServices: new[] { new RunningService { Name = "ssh.service", State = "active/running" } },
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_IgnoresFindingsWithoutRuleId()
    {
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Critical,
            Confidence = DetectionConfidence.Low,
            SourceHost = "localhost",
            Target = "test",
            ShortDescription = "test",
            Details = "test",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow
        };
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    [Fact]
    public void Validate_EmitsWarning_WhenPredicateThrows()
    {
        var registry = new Dictionary<string, Func<Finding, ScanData, CrossScannerValidationSignal?>>(StringComparer.OrdinalIgnoreCase)
        {
            ["THROW-001"] = (f, d) => throw new InvalidOperationException("predicate failure")
        };
        var validator = new CrossScannerValidator(registry);
        var finding = CreateFinding("THROW-001", Severity.High, "target", DetectionConfidence.Low);
        var warnings = new List<string>();

        var result = validator.Validate(new[] { finding }, CreateScanData(), warnings);

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Contains(warnings, w => w.Contains("THROW-001") && w.Contains("predicate failure"));
    }

    // =====================================================================
    // Firewall rule validators
    // =====================================================================

    [Fact]
    public void Validate_DoesNotValidateFw001OrFw004()
    {
        // FW-001 and FW-004 have no independent cross-check by design.
        var finding001 = CreateFinding("FW-001", Severity.High, "INPUT", DetectionConfidence.Low);
        var finding004 = CreateFinding("FW-004", Severity.Critical, "firewall", DetectionConfidence.Low);
        var scanData = CreateScanData(firewallActive: false);

        var result = _validator.Validate(new[] { finding001, finding004 }, scanData, new List<string>());

        Assert.All(result, f =>
        {
            Assert.Equal(DetectionConfidence.Low, f.Confidence);
            Assert.Empty(f.EvidenceSignals);
        });
    }

    // =====================================================================
    // Service validators
    // =====================================================================

    [Theory]
    [InlineData("SRV-001", 23)]
    [InlineData("SRV-002", 21)]
    [InlineData("SRV-004", 513)]
    public void Validate_SupportsServiceRule_WhenPortListening(string ruleId, int port)
    {
        var finding = CreateFinding(ruleId, Severity.Critical, "service", DetectionConfidence.Low);
        var scanData = CreateScanData(
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = port, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Theory]
    [InlineData("SRV-001")]
    [InlineData("SRV-002")]
    [InlineData("SRV-004")]
    public void Validate_ContradictsServiceRule_WhenPortNotListening(string ruleId)
    {
        var finding = CreateFinding(ruleId, Severity.Critical, "service", DetectionConfidence.Low);
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    // =====================================================================
    // SSH validators
    // =====================================================================

    [Theory]
    [InlineData("SSH-001")]
    [InlineData("SSH-004")]
    [InlineData("SSH-005")]
    public void Validate_SupportsSshRules_WhenReachable(string ruleId)
    {
        var finding = CreateFinding(ruleId, Severity.Critical, "sshd", DetectionConfidence.Low);
        var scanData = CreateScanData(
            runningServices: new[] { new RunningService { Name = "ssh.service", State = "active/running" } },
            openPorts: new[] { new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 22, State = "LISTEN" } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsSsh006_WhenPubkeyDisabledButSshNotReachable()
    {
        var finding = CreateFinding("SSH-006", Severity.High, "PubkeyAuthentication no", DetectionConfidence.Low);
        var scanData = CreateScanData();

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    // =====================================================================
    // Network validators
    // =====================================================================

    [Fact]
    public void Validate_SupportsNet002_WhenActiveConnectionsExist()
    {
        var finding = CreateFinding("NET-002", Severity.High, "192.0.2.1:23", DetectionConfidence.Low);
        var scanData = CreateScanData(
            activeConnections: new[]
            {
                new ActiveConnection
                {
                    LocalAddress = "10.0.0.5",
                    LocalPort = 54321,
                    RemoteAddress = "192.0.2.1",
                    RemotePort = 23,
                    State = "ESTAB"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_DoesNotValidateNet003()
    {
        // NET-003 has no independent cross-check by design.
        var finding = CreateFinding("NET-003", Severity.High, "interfaces", DetectionConfidence.Low);
        var scanData = CreateScanData(
            networkInterfaces: new[] { new NetworkInterface { Name = "eth0", IsUp = true, Addresses = new[] { "192.168.1.10" } } });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Low, validated.Confidence);
        Assert.Empty(validated.EvidenceSignals);
    }

    // =====================================================================
    // Container / Kubernetes validators
    // =====================================================================

    [Fact]
    public void Validate_DoesNotValidateContainerAndKubernetesRules()
    {
        // CTR-* and K8S-* rules read the same Containers/KubernetesPods scan data a
        // validator would read, so there is no independent cross-check by design.
        // Findings must pass through unchanged (no confidence move, no signal).
        var ctr001 = CreateFinding("CTR-001", Severity.Critical, "web", DetectionConfidence.Low);
        var ctr002 = CreateFinding("CTR-002", Severity.High, "web", DetectionConfidence.Low);
        var ctr003 = CreateFinding("CTR-003", Severity.Critical, "docker.sock", DetectionConfidence.Low);
        var ctr005 = CreateFinding("CTR-005", Severity.High, "app", DetectionConfidence.Low);
        var k8s001 = CreateFinding("K8S-001", Severity.Critical, "default/web", DetectionConfidence.Low);
        var k8s002 = CreateFinding("K8S-002", Severity.High, "default/web", DetectionConfidence.Low);
        var k8s003 = CreateFinding("K8S-003", Severity.High, "default/web", DetectionConfidence.Low);

        var scanData = CreateScanData(
            containers: new[]
            {
                new ContainerInfo { Name = "web", Image = "nginx", Tag = "latest", IsPrivileged = true, KnownBadBaseLayers = new[] { "ubuntu:14.04" }, HasDockerSocketMount = true }
            },
            containerRuntime: new ContainerRuntimeInfo { DockerSocketExposed = true },
            kubernetesPods: new[]
            {
                new KubernetesPodInfo
                {
                    Namespace = "default",
                    Name = "web",
                    HostNetwork = true,
                    Containers = new[] { new K8sContainerInfo { Name = "app", Privileged = true, RunAsRoot = true } }
                }
            });

        var result = _validator.Validate(new[] { ctr001, ctr002, ctr003, ctr005, k8s001, k8s002, k8s003 }, scanData, new List<string>());

        Assert.All(result, f =>
        {
            Assert.Equal(DetectionConfidence.Low, f.Confidence);
            Assert.Empty(f.EvidenceSignals);
        });
    }

    [Fact]
    public void Validate_UsesVariablesPort_WhenTargetHasNoPort()
    {
        var finding = CreateFinding("PORT-003", Severity.Critical, "database", DetectionConfidence.Low)
            with { Variables = new Dictionary<string, string> { ["port"] = "5432" } };
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "ACCEPT",
                    DestinationPort = "5432",
                    RawLine = "ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:5432"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static Finding CreateFinding(string ruleId, Severity severity, string target, DetectionConfidence confidence = DetectionConfidence.Unknown)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            Confidence = confidence,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = "test",
            Details = "test",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static void AssertSupport(Finding finding)
    {
        var signal = Assert.Single(finding.EvidenceSignals, s => s.Source == CrossScannerValidationSignal.SourceName);
        Assert.StartsWith("Supports:", signal.Name, StringComparison.Ordinal);
    }

    private static void AssertContradiction(Finding finding)
    {
        var signal = Assert.Single(finding.EvidenceSignals, s => s.Source == CrossScannerValidationSignal.SourceName);
        Assert.StartsWith("Contradicts:", signal.Name, StringComparison.Ordinal);
    }

    private static ScanData CreateScanData(
        IEnumerable<DataSourceCapability>? capabilities = null,
        IEnumerable<OpenPort>? openPorts = null,
        IEnumerable<NetworkInterface>? networkInterfaces = null,
        IEnumerable<RunningService>? runningServices = null,
        IEnumerable<ActiveConnection>? activeConnections = null,
        bool firewallActive = false,
        IEnumerable<FirewallRule>? firewallRules = null,
        ContainerRuntimeInfo? containerRuntime = null,
        IEnumerable<ContainerInfo>? containers = null,
        IEnumerable<KubernetesPodInfo>? kubernetesPods = null)
    {
        return new ScanData
        {
            Capabilities = (capabilities ?? DefaultCapabilities()).ToList(),
            OpenPorts = (openPorts ?? Array.Empty<OpenPort>()).ToList(),
            NetworkInterfaces = (networkInterfaces ?? Array.Empty<NetworkInterface>()).ToList(),
            RunningServices = (runningServices ?? Array.Empty<RunningService>()).ToList(),
            ActiveConnections = (activeConnections ?? Array.Empty<ActiveConnection>()).ToList(),
            FirewallActive = firewallActive,
            FirewallRules = (firewallRules ?? Array.Empty<FirewallRule>()).ToList(),
            ContainerRuntime = containerRuntime,
            Containers = (containers ?? Array.Empty<ContainerInfo>()).ToList(),
            KubernetesPods = (kubernetesPods ?? Array.Empty<KubernetesPodInfo>()).ToList()
        };
    }

    private static IEnumerable<DataSourceCapability> DefaultCapabilities()
    {
        return new[]
        {
            new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "netstat", Status = CapabilityStatus.Unknown },
            new DataSourceCapability { SourceName = "systemctl", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "ip addr", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "ss connections", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "iptables", Status = CapabilityStatus.Available },
            new DataSourceCapability { SourceName = "nftables", Status = CapabilityStatus.Unknown }
        };
    }
}
