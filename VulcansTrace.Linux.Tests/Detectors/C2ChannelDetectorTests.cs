using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Detectors;

public class C2ChannelDetectorTests
{
    private static AnalysisProfile C2Profile() => new()
    {
        EnableC2Detection = true,
        C2ToleranceSeconds = 5.0,
        C2MinIntervalSeconds = 10,
        C2MaxIntervalSeconds = 120,
        C2MinOccurrences = 3,
        C2MinPatternEvents = 4
    };

    private static UnifiedEvent MakeEvent(DateTime timestamp, string srcIp = "192.168.1.100",
        string dstIp = "10.0.0.50", int dstPort = 443) => new()
    {
        Timestamp = timestamp,
        SourceIP = srcIp,
        DestinationIP = dstIp,
        DestinationPort = dstPort,
        Protocol = "TCP",
        LogFormat = LogFormat.Iptables,
        SourcePort = 54321
    };

    [Fact]
    public void C2ChannelDetector_Detect_WithPeriodicPattern_FindsC2Channel()
    {
        var baseTime = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => MakeEvent(baseTime.AddSeconds(i * 30)))
            .ToList();

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings;

        Assert.NotEmpty(findings);
        var finding = findings.First();
        Assert.Equal("C2Channel", finding.Category);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("Potential C2 channel detected", finding.ShortDescription);
    }

    [Fact]
    public void C2ChannelDetector_Detect_Disabled_NotRun()
    {
        var events = new List<UnifiedEvent>
        {
            MakeEvent(DateTime.UtcNow),
            MakeEvent(DateTime.UtcNow.AddSeconds(30))
        };

        var profile = new AnalysisProfile { EnableC2Detection = false };
        var detector = new C2ChannelDetector();

        Assert.Empty(detector.Detect(events, profile, CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_NoPattern_NotDetected()
    {
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>
        {
            MakeEvent(baseTime),
            MakeEvent(baseTime.AddSeconds(10)),
            MakeEvent(baseTime.AddSeconds(50))
        };

        var detector = new C2ChannelDetector();
        Assert.Empty(detector.Detect(events, C2Profile(), CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_JitterAtBucketBoundary_ReturnsFinding()
    {
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>
        {
            MakeEvent(baseTime),
            MakeEvent(baseTime.AddSeconds(60)),
            MakeEvent(baseTime.AddSeconds(124)),
            MakeEvent(baseTime.AddSeconds(185))
        };

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings;

        Assert.Single(findings);
        Assert.Equal(FindingCategories.C2Channel, findings[0].Category);
        Assert.Equal(EngineRuleIds.C2Channel, findings[0].RuleId);
    }

    [Fact]
    public void C2ChannelDetector_Detect_MultipleConnections_ReportsFindingsPerConnection()
    {
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();

        for (int i = 0; i < 8; i++)
            events.Add(MakeEvent(baseTime.AddSeconds(i * 30), dstPort: 443));

        for (int i = 0; i < 8; i++)
            events.Add(MakeEvent(baseTime.AddSeconds(i * 60), dstPort: 8443));

        events = events.OrderBy(e => e.Timestamp).ToList();

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings.ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("C2Channel", f.Category));
    }

    [Fact]
    public void C2ChannelDetector_Detect_EmptyEvents_ReturnsNoFindings()
    {
        var detector = new C2ChannelDetector();
        var events = Array.Empty<UnifiedEvent>();

        Assert.Empty(detector.Detect(events, C2Profile(), CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_ToleranceZero_ReturnsNoFindings()
    {
        var baseTime = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => MakeEvent(baseTime.AddSeconds(i * 30)))
            .ToList();

        var profile = C2Profile() with { C2ToleranceSeconds = 0 };
        var detector = new C2ChannelDetector();

        Assert.Empty(detector.Detect(events, profile, CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_ToleranceNegative_ReturnsNoFindings()
    {
        var baseTime = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => MakeEvent(baseTime.AddSeconds(i * 30)))
            .ToList();

        var profile = C2Profile() with { C2ToleranceSeconds = -1 };
        var detector = new C2ChannelDetector();

        Assert.Empty(detector.Detect(events, profile, CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_BelowMinGroupSize_NoPattern()
    {
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>
        {
            MakeEvent(baseTime),
            MakeEvent(baseTime.AddSeconds(30))
        };

        var detector = new C2ChannelDetector();
        Assert.Empty(detector.Detect(events, C2Profile(), CancellationToken.None).Findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_FindingProperties_AreCorrect()
    {
        var baseTime = DateTime.UtcNow;
        var events = Enumerable.Range(0, 5)
            .Select(i => MakeEvent(baseTime.AddSeconds(i * 30), srcIp: "10.0.0.5", dstIp: "192.168.1.50", dstPort: 8080))
            .ToList();

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings.ToList();

        Assert.Single(findings);
        var f = findings[0];
        Assert.Equal("C2Channel", f.Category);
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal("10.0.0.5", f.SourceHost);
        Assert.Equal("192.168.1.50:8080", f.Target);
        Assert.True(f.TimeRangeEnd >= f.TimeRangeStart);
        Assert.Contains("30", f.Details);
    }

    [Fact]
    public void C2ChannelDetector_Detect_ExactMinGroupSize_ReturnsFinding()
    {
        // Boundary: exactly 3 events with a profile where minGroupSize=3,
        // minOccurrences=2 and minPatternEvents=3 are the only other constraints.
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>
        {
            MakeEvent(baseTime),
            MakeEvent(baseTime.AddSeconds(30)),
            MakeEvent(baseTime.AddSeconds(60))
        };

        var profile = C2Profile() with { C2MinOccurrences = 2, C2MinPatternEvents = 3 };
        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, profile, CancellationToken.None).Findings;
        Assert.NotEmpty(findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_ExactMinOccurrences_ReturnsFinding()
    {
        // Boundary: exactly 3 occurrences of the same delta (default min occurrences)
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        // Create 4 events with 3 identical 30s deltas
        for (int i = 0; i < 4; i++)
        {
            events.Add(MakeEvent(baseTime.AddSeconds(i * 30)));
        }

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings;
        Assert.NotEmpty(findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_ExactMinPatternEvents_ReturnsFinding()
    {
        // Boundary: exactly 4 events participating in the pattern (default min pattern events)
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();
        for (int i = 0; i < 4; i++)
        {
            events.Add(MakeEvent(baseTime.AddSeconds(i * 30)));
        }

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings;
        Assert.NotEmpty(findings);
    }

    [Fact]
    public void C2ChannelDetector_Detect_TwoFrequenciesOnSameConnection_ReportsBothFindings()
    {
        var baseTime = DateTime.UtcNow;
        var events = new List<UnifiedEvent>();

        for (int i = 0; i < 6; i++)
            events.Add(MakeEvent(baseTime.AddSeconds(i * 30)));

        for (int i = 0; i < 6; i++)
            events.Add(MakeEvent(baseTime.AddSeconds(180 + i * 60)));

        events = events.OrderBy(e => e.Timestamp).ToList();

        var detector = new C2ChannelDetector();
        var findings = detector.Detect(events, C2Profile(), CancellationToken.None).Findings.ToList();

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("C2Channel", f.Category));
        Assert.Contains(findings, f => f.Details.Contains("30"));
        Assert.Contains(findings, f => f.Details.Contains("60"));
    }
}
