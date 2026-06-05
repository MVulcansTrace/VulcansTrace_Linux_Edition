using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Tests.Engine;

public class LogDiffAnalyzerTests
{
    private readonly LogDiffAnalyzer _analyzer = new();
    private static readonly DateTime BaseTime = new(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Compare_EmptyBaseline_AllAdded()
    {
        var baseline = new AnalysisResult();
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Added, result.Events[0].State);
        Assert.Equal(0, result.Events[0].BaselineCount);
        Assert.Equal(1, result.Events[0].IncidentCount);
        Assert.Equal("10.0.0.1:*-192.168.1.1:54321-TCP", result.Events[0].ConnectionKey);
    }

    [Fact]
    public void Compare_EmptyIncident_AllRemoved()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT")
        );
        var incident = new AnalysisResult();

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Removed, result.Events[0].State);
        Assert.Equal(1, result.Events[0].BaselineCount);
        Assert.Equal(0, result.Events[0].IncidentCount);
    }

    [Fact]
    public void Compare_IdenticalResults_AllUnchanged()
    {
        var e1 = CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT");
        var baseline = CreateAnalysisResult(e1);
        var incident = CreateAnalysisResult(e1);

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Unchanged, result.Events[0].State);
    }

    [Fact]
    public void Compare_CountDeltaAboveThreshold_MarksChanged()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT")
        );
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Changed, result.Events[0].State);
        Assert.Equal(1, result.Events[0].BaselineCount);
        Assert.Equal(3, result.Events[0].IncidentCount);
    }

    [Fact]
    public void Compare_SourcePortChurn_StillMatchesSameTrafficPattern()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 49152, "192.168.1.1", 443, "TCP", "ACCEPT")
        );
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 49153, "192.168.1.1", 443, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.1", 49154, "192.168.1.1", 443, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.1", 49155, "192.168.1.1", 443, "TCP", "ACCEPT")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Changed, result.Events[0].State);
        Assert.Equal("10.0.0.1:*-192.168.1.1:443-TCP", result.Events[0].ConnectionKey);
        Assert.Equal(1, result.Events[0].BaselineCount);
        Assert.Equal(3, result.Events[0].IncidentCount);
    }

    [Fact]
    public void Compare_ActionDistributionChange_MarksChanged()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "ACCEPT")
        );
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 54321, "TCP", "DROP")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Events);
        Assert.Equal(LogDiffState.Changed, result.Events[0].State);
    }

    [Fact]
    public void Compare_MultipleKeys_MixedStates()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 1000, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.2", 443, "192.168.1.1", 2000, "TCP", "ACCEPT")
        );
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 1000, "TCP", "ACCEPT"),
            CreateEvent("10.0.0.3", 22, "192.168.1.1", 3000, "TCP", "ACCEPT")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Equal(3, result.Events.Count);
        Assert.Contains(result.Events, e => e.State == LogDiffState.Unchanged && e.ConnectionKey.Contains("10.0.0.1"));
        Assert.Contains(result.Events, e => e.State == LogDiffState.Removed && e.ConnectionKey.Contains("10.0.0.2"));
        Assert.Contains(result.Events, e => e.State == LogDiffState.Added && e.ConnectionKey.Contains("10.0.0.3"));
    }

    [Fact]
    public void Compare_FindingAdded()
    {
        var baseline = new AnalysisResult();
        var incident = CreateAnalysisResultWithFinding(
            CreateFinding(FindingCategories.PortScan, Severity.High, "10.0.0.1", "192.168.1.1:80")
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Findings);
        Assert.Equal(LogDiffState.Added, result.Findings[0].State);
    }

    [Fact]
    public void Compare_FindingRemoved()
    {
        var baseline = CreateAnalysisResultWithFinding(
            CreateFinding(FindingCategories.PortScan, Severity.High, "10.0.0.1", "192.168.1.1:80")
        );
        var incident = new AnalysisResult();

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Findings);
        Assert.Equal(LogDiffState.Removed, result.Findings[0].State);
    }

    [Fact]
    public void Compare_FindingSeverityChanged()
    {
        var f1 = CreateFinding(FindingCategories.PortScan, Severity.Medium, "10.0.0.1", "192.168.1.1:80");
        var f2 = CreateFinding(FindingCategories.PortScan, Severity.High, "10.0.0.1", "192.168.1.1:80");

        var baseline = CreateAnalysisResultWithFinding(f1);
        var incident = CreateAnalysisResultWithFinding(f2);

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Findings);
        Assert.Equal(LogDiffState.Changed, result.Findings[0].State);
        Assert.Equal(Severity.Medium, result.Findings[0].OldSeverity);
        Assert.Equal(Severity.High, result.Findings[0].NewSeverity);
    }

    [Fact]
    public void Compare_FindingUnchanged()
    {
        var f = CreateFinding(FindingCategories.PortScan, Severity.High, "10.0.0.1", "192.168.1.1:80");
        var baseline = CreateAnalysisResultWithFinding(f);
        var incident = CreateAnalysisResultWithFinding(f);

        var result = _analyzer.Compare(baseline, incident);

        Assert.Single(result.Findings);
        Assert.Equal(LogDiffState.Unchanged, result.Findings[0].State);
    }

    [Fact]
    public void Compare_PreservesTimeRanges()
    {
        var baseline = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 1000, "TCP", "ACCEPT", BaseTime)
        );
        var incident = CreateAnalysisResult(
            CreateEvent("10.0.0.1", 80, "192.168.1.1", 1000, "TCP", "ACCEPT", BaseTime.AddHours(1))
        );

        var result = _analyzer.Compare(baseline, incident);

        Assert.Equal(BaseTime, result.BaselineTimeRangeStart);
        Assert.Equal(BaseTime, result.BaselineTimeRangeEnd);
        Assert.Equal(BaseTime.AddHours(1), result.IncidentTimeRangeStart);
        Assert.Equal(BaseTime.AddHours(1), result.IncidentTimeRangeEnd);
    }

    private static UnifiedEvent CreateEvent(
        string srcIp, int srcPort, string dstIp, int dstPort, string protocol, string action,
        DateTime? timestamp = null)
    {
        return new UnifiedEvent
        {
            Timestamp = timestamp ?? BaseTime,
            SourceIP = srcIp,
            SourcePort = srcPort,
            DestinationIP = dstIp,
            DestinationPort = dstPort,
            Protocol = protocol,
            Action = action,
            LogFormat = LogFormat.Iptables
        };
    }

    private static Finding CreateFinding(string category, Severity severity, string sourceHost, string target)
    {
        return new Finding
        {
            Category = category,
            Severity = severity,
            SourceHost = sourceHost,
            Target = target,
            TimeRangeStart = BaseTime,
            TimeRangeEnd = BaseTime.AddMinutes(5),
            ShortDescription = "Test finding",
            Details = "Test details"
        };
    }

    private static AnalysisResult CreateAnalysisResult(params UnifiedEvent[] events)
    {
        return new AnalysisResult
        {
            Entries = events.ToList(),
            ParsedLines = events.Length,
            TotalLines = events.Length,
            TimeRangeStart = events.Length > 0 ? events.Min(e => e.Timestamp) : DateTime.MinValue,
            TimeRangeEnd = events.Length > 0 ? events.Max(e => e.Timestamp) : DateTime.MinValue
        };
    }

    private static AnalysisResult CreateAnalysisResultWithFinding(Finding finding)
    {
        return new AnalysisResult
        {
            Findings = new List<Finding> { finding },
            Entries = Array.Empty<UnifiedEvent>(),
            TimeRangeStart = BaseTime,
            TimeRangeEnd = BaseTime.AddMinutes(5)
        };
    }
}
