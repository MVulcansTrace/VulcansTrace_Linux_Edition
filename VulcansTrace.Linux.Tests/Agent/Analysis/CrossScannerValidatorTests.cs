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
    public void Validate_ProcessesMediumFindings()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: false,
            firewallRules: Array.Empty<FirewallRule>());

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
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
    public void Validate_SupportsPort002_WhenNoFirewall()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: false,
            firewallRules: Array.Empty<FirewallRule>());

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_SupportsPort002_WhenFirewallAcceptsPort()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "ACCEPT",
                    Source = "0.0.0.0/0",
                    DestinationPort = "8080",
                    RawLine = "ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:8080"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_ContradictsPort002_WhenFirewallBlocksPort()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "DROP",
                    DestinationPort = "8080",
                    RawLine = "DROP tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:8080"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Unknown, validated.Confidence);
        AssertContradiction(validated);
    }

    [Fact]
    public void Validate_SupportsPort002_WhenNftablesAcceptsPort()
    {
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:8080", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "input",
                    Target = "accept",
                    DestinationPort = "8080",
                    RawLine = "tcp dport 8080 accept"
                }
            });

        var result = _validator.Validate(new[] { finding }, scanData, new List<string>());

        var validated = Assert.Single(result);
        Assert.Equal(DetectionConfidence.Medium, validated.Confidence);
        AssertSupport(validated);
    }

    [Fact]
    public void Validate_DoesNotValidatePort002_OnPortPrefixSubstring()
    {
        // Port 80 must not match inside "dpt:8080" or "dport 8080".
        var finding = CreateFinding("PORT-002", Severity.Medium, "0.0.0.0:80", DetectionConfidence.Low);
        var scanData = CreateScanData(
            firewallActive: true,
            firewallRules: new[]
            {
                new FirewallRule
                {
                    Chain = "INPUT",
                    Target = "ACCEPT",
                    RawLine = "ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 dpt:8080"
                }
            });

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
        IEnumerable<FirewallRule>? firewallRules = null)
    {
        return new ScanData
        {
            Capabilities = (capabilities ?? DefaultCapabilities()).ToList(),
            OpenPorts = (openPorts ?? Array.Empty<OpenPort>()).ToList(),
            NetworkInterfaces = (networkInterfaces ?? Array.Empty<NetworkInterface>()).ToList(),
            RunningServices = (runningServices ?? Array.Empty<RunningService>()).ToList(),
            ActiveConnections = (activeConnections ?? Array.Empty<ActiveConnection>()).ToList(),
            FirewallActive = firewallActive,
            FirewallRules = (firewallRules ?? Array.Empty<FirewallRule>()).ToList()
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
