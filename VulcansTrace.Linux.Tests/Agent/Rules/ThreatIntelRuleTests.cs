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
    public void ThreatIntelIpRule_NoMatches_Passes()
    {
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelIpRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
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
    public void ThreatIntelPortRule_NoMatches_Passes()
    {
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelPortRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
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
    public void ThreatIntelHashRule_NoMatches_Passes()
    {
        var store = new InMemoryThreatIntelStore();
        var rule = new ThreatIntelHashRule(store);
        var data = new ScanData();

        var result = rule.Evaluate(data);

        Assert.True(result.Passed);
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
