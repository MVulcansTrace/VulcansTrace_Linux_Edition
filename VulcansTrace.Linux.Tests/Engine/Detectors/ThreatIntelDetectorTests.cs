using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Engine.Detectors;

public class ThreatIntelDetectorTests
{
    private static AnalysisProfile Profile => new AnalysisProfileProvider().GetProfile(IntensityLevel.Medium);

    [Fact]
    public void Detect_EmptyStore_ReturnsNoFindings()
    {
        var store = new InMemoryThreatIntelStore();
        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 80) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Detect_MatchingSourceIp_CreatesFinding()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", ThreatScore = 85, Source = "STIX" } });

        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 80) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Single(result.Findings);
        Assert.Equal(FindingCategories.ThreatIntel, result.Findings[0].Category);
        Assert.Equal(EngineRuleIds.ThreatIntel, result.Findings[0].RuleId);
        Assert.Equal(Severity.Critical, result.Findings[0].Severity);
    }

    [Fact]
    public void Detect_MatchingDestinationIp_CreatesFinding()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "10.0.0.1", ThreatScore = 65, Source = "MISP" } });

        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 80) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Single(result.Findings);
        Assert.Equal(Severity.High, result.Findings[0].Severity);
    }

    [Fact]
    public void Detect_MatchingPort_CreatesFinding()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 45, Source = "STIX" } });

        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 4444) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Single(result.Findings);
        Assert.Equal(Severity.Medium, result.Findings[0].Severity);
    }

    [Fact]
    public void Detect_LowConfidence_CreatesLowSeverityFinding()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", ThreatScore = 30, Source = "STIX" } });

        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 80) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Single(result.Findings);
        Assert.Equal(Severity.Low, result.Findings[0].Severity);
    }

    [Fact]
    public void Detect_NoMatch_ReturnsEmpty()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 90, Source = "STIX" } });

        var detector = new ThreatIntelDetector(store);
        var events = new[] { CreateEvent("192.168.1.1", "10.0.0.1", 80) };

        var result = detector.Detect(events, Profile, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    private static UnifiedEvent CreateEvent(string srcIp, string dstIp, int dstPort)
    {
        return new UnifiedEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceIP = srcIp,
            DestinationIP = dstIp,
            SourcePort = 12345,
            DestinationPort = dstPort,
            Protocol = "TCP",
            Action = "ACCEPT",
            LogFormat = LogFormat.Iptables
        };
    }
}
