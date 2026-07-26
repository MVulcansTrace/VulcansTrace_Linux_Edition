using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.Rules;

public class ThreatIntelRuleTests
{
    [Fact]
    public void ThreatIntelIpRule_NoIntel_NotApplicable()
    {
        // No IOCs imported and no connections collected — can't tell "clean" from "never checked",
        // so this is not applicable rather than a clean pass.
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelIpRule_CleanConnection_Passes()
    {
        // True negative: intel present, connections present, none match -> genuine pass.
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 75 } });

        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData
        {
            ActiveConnections = new[]
            {
                new ActiveConnection { RemoteAddress = "5.6.7.8", RemotePort = 443, Protocol = "TCP", State = "ESTAB" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelIpRule_MatchingConnection_Fails()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 75 } });

        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData
        {
            ActiveConnections = new[]
            {
                new ActiveConnection { RemoteAddress = "1.2.3.4", RemotePort = 80, Protocol = "TCP", State = "ESTAB" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.High, result.Severity);
    }

    [Fact]
    public void ThreatIntelIpRule_IntelPresentNoConnectionsButScanRan_Passes()
    {
        // Genuine quiet host: intel loaded, connection scan ran and found nothing -> clean pass,
        // not "not applicable" (empty data must not be conflated with "never ran").
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 75 } });

        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData
        {
            Capabilities = new[] { new DataSourceCapability { SourceName = "ss connections", Status = CapabilityStatus.Available } }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelIpRule_IntelPresentNoConnectionsScanNeverRan_NotApplicable()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 75 } });

        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelPortRule_NoIntel_NotApplicable()
    {
        // No port IOCs and no open ports collected -> not applicable, not a clean pass.
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelPortRule_CleanPort_Passes()
    {
        // True negative: a malicious port IOC is loaded, but the host listens on a different port.
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 50 } });

        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 8080, Protocol = "TCP", State = "LISTEN" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelPortRule_MatchingPort_Fails()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 50 } });

        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData
        {
            OpenPorts = new[]
            {
                new OpenPort { LocalAddress = "0.0.0.0", LocalPort = 4444, Protocol = "TCP", State = "LISTEN" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Medium, result.Severity);
    }

    [Fact]
    public void ThreatIntelPortRule_IntelPresentNoPortsButScanRan_Passes()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 50 } });

        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData
        {
            Capabilities = new[] { new DataSourceCapability { SourceName = "ss", Status = CapabilityStatus.Available } }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelPortRule_IntelPresentNoPortsScanNeverRan_NotApplicable()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 50 } });

        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_IntelPresentNoHashesButScanRan_Passes()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.FileHash, Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", ThreatScore = 90 } });

        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData
        {
            Capabilities = new[] { new DataSourceCapability { SourceName = "file-hash", Status = CapabilityStatus.Available } }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_IntelPresentNoHashesScanNeverRan_NotApplicable()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.FileHash, Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", ThreatScore = 90 } });

        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_IntelPresentNoHashesPermissionLimited_NotApplicable()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[]
        {
            new IocEntry
            {
                Type = IocType.FileHash,
                Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                Algorithm = "SHA-256",
                ThreatScore = 90
            }
        });
        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData
        {
            Capabilities = new[]
            {
                new DataSourceCapability
                {
                    SourceName = "file-hash",
                    Status = CapabilityStatus.PermissionLimited
                }
            }
        };

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_NoIntel_NotApplicable()
    {
        // No hash IOCs and no file hashes collected -> not applicable, not a clean pass.
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_CleanHash_Passes()
    {
        // True negative: a malicious hash IOC is loaded, but the scanned file has a different hash.
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.FileHash, Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", ThreatScore = 90 } });

        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData
        {
            FileHashes = new[]
            {
                new FileHashEntry { Path = "/tmp/clean", Hash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
        Assert.Equal(RuleStatus.Passed, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_CleanObservedHashButScanIncomplete_NotApplicable()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[]
        {
            new IocEntry
            {
                Type = IocType.FileHash,
                Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                ThreatScore = 90
            }
        });
        var data = new ScanData
        {
            FileHashes = new[]
            {
                new FileHashEntry
                {
                    Path = "/tmp/clean",
                    Hash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                }
            },
            Capabilities = new[]
            {
                new DataSourceCapability
                {
                    SourceName = "file-hash",
                    Status = CapabilityStatus.PermissionLimited
                }
            }
        };

        var result = new ThreatIntelHashRule(store).Evaluate(data);

        Assert.Equal(RuleStatus.NotApplicable, result.Status);
    }

    [Fact]
    public void ThreatIntelHashRule_MatchingHash_Fails()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.FileHash, Value = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", ThreatScore = 90 } });

        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData
        {
            FileHashes = new[]
            {
                new FileHashEntry { Path = "/tmp/evil", Hash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public void ThreatIntelHashRule_CaseInsensitiveMatch_Fails()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.FileHash, Value = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899", ThreatScore = 90 } });

        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData
        {
            FileHashes = new[]
            {
                new FileHashEntry { Path = "/tmp/evil", Hash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }
            }
        };

        var result = rule.Evaluate(data);

        Assert.False(result.Passed);
    }
}
