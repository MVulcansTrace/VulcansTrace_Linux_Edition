using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Memory;

public class RuleMemoryRecorderTests
{
    private readonly RuleMemoryRecorder _recorder = new();

    [Fact]
    public void Record_FirstObservation_CreatesNewEntry()
    {
        var result = CreateResult("FW-001", Severity.High);

        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());

        Assert.Single(history);
        var entry = history["FW-001"];
        Assert.Equal("FW-001", entry.RuleId);
        Assert.Equal(RuleStatusTrend.New, entry.Trend);
        Assert.Single(entry.SeverityHistory);
        Assert.Equal(Severity.High, entry.LastSeverity);
    }

    [Fact]
    public void Record_SecondObservationSameSeverity_MarksStable()
    {
        var first = CreateResult("FW-001", Severity.High, utc: DateTime.UtcNow.AddDays(-1));
        var second = CreateResult("FW-001", Severity.High);

        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(second, history);

        var entry = history["FW-001"];
        Assert.Equal(RuleStatusTrend.Stable, entry.Trend);
        Assert.Equal(2, entry.SeverityHistory.Count);
    }

    [Fact]
    public void Record_SeverityIncrease_MarksWorsening()
    {
        var first = CreateResult("FW-001", Severity.Medium, utc: DateTime.UtcNow.AddDays(-1));
        var second = CreateResult("FW-001", Severity.High);

        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(second, history);

        var entry = history["FW-001"];
        Assert.Equal(RuleStatusTrend.Worsening, entry.Trend);
    }

    [Fact]
    public void Record_SeverityDecrease_MarksImproving()
    {
        var first = CreateResult("FW-001", Severity.High, utc: DateTime.UtcNow.AddDays(-1));
        var second = CreateResult("FW-001", Severity.Low);

        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(second, history);

        var entry = history["FW-001"];
        Assert.Equal(RuleStatusTrend.Improving, entry.Trend);
    }

    [Fact]
    public void Record_PreservesRemediationAttemptAndConsumesVerifiedFixed()
    {
        var first = CreateResult("FW-001", Severity.High, utc: DateTime.UtcNow.AddDays(-2));
        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        var verifiedUtc = DateTime.UtcNow;
        var existing = history["FW-001"] with
        {
            LastRemediationAttemptUtc = DateTime.UtcNow.AddDays(-1),
            LastVerifiedFixedUtc = verifiedUtc
        };
        history = new Dictionary<string, RuleMemoryEntry>(history, StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = existing
        };

        var second = CreateResult("FW-001", Severity.High);
        history = _recorder.Record(second, history);

        var entry = history["FW-001"];
        Assert.Equal(existing.LastRemediationAttemptUtc, entry.LastRemediationAttemptUtc);
        Assert.Null(entry.LastVerifiedFixedUtc);
        Assert.Single(entry.RemediationCycles);
        Assert.Equal(verifiedUtc, entry.RemediationCycles[0].VerifiedFixedUtc);
        Assert.True(entry.RemediationCycles[0].IsClosed);
    }

    [Fact]
    public void Record_MultipleRules_TracksEachIndependently()
    {
        var result = CreateResult(new[]
        {
            ("FW-001", Severity.High),
            ("SSH-002", Severity.Critical)
        });

        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());

        Assert.Equal(2, history.Count);
        Assert.Equal("Firewall", history["FW-001"].Category);
        Assert.Equal("SSH", history["SSH-002"].Category);
    }

    [Fact]
    public void Record_FindingWithoutRuleId_IsIgnored()
    {
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding
                {
                    Category = "Unknown",
                    Severity = Severity.High,
                    SourceHost = "localhost",
                    Target = "something",
                    ShortDescription = "No rule id",
                    Details = "Details",
                    TimeRangeStart = DateTime.UtcNow,
                    TimeRangeEnd = DateTime.UtcNow
                }
            },
            UtcTimestamp = DateTime.UtcNow
        };

        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());

        Assert.Empty(history);
    }

    [Fact]
    public void Record_OldSnapshotsArePruned()
    {
        var now = DateTime.UtcNow;
        var old = CreateResult("FW-001", Severity.High, utc: now.AddDays(-100));
        var recent = CreateResult("FW-001", Severity.High, utc: now.AddDays(-1));
        var current = CreateResult("FW-001", Severity.High, utc: now);

        var history = _recorder.Record(old, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(recent, history);
        history = _recorder.Record(current, history);

        var entry = history["FW-001"];
        Assert.Equal(2, entry.SeverityHistory.Count);
        Assert.All(entry.SeverityHistory, s => Assert.True(s.UtcTimestamp >= now.AddDays(-90)));
    }



    [Fact]
    public void Record_CaseInsensitiveRuleIdLookup()
    {
        var first = CreateResult("FW-001", Severity.High);
        var second = CreateResult("fw-001", Severity.High);

        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(second, history);

        Assert.Single(history);
        Assert.Equal(2, history["FW-001"].SeverityHistory.Count);
    }

    [Fact]
    public void MarkVerifiedFixed_SetsTimestampOnExistingEntry()
    {
        var result = CreateResult("FW-001", Severity.High);
        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());
        var timestamp = new DateTime(2026, 6, 18, 12, 0, 0, DateTimeKind.Utc);

        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, timestamp, history);

        Assert.Equal(timestamp, history["FW-001"].LastVerifiedFixedUtc);
    }

    [Fact]
    public void MarkVerifiedFixed_UnknownRuleId_IsIgnored()
    {
        var history = _recorder.MarkVerifiedFixed(new[] { "UNKNOWN-001" }, DateTime.UtcNow, new Dictionary<string, RuleMemoryEntry>());

        Assert.Empty(history);
    }

    [Fact]
    public void MarkRemediationAttempt_SetsTimestampOnExistingEntry()
    {
        var result = CreateResult("FW-001", Severity.High);
        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());
        var timestamp = new DateTime(2026, 6, 18, 12, 0, 0, DateTimeKind.Utc);

        history = _recorder.MarkRemediationAttempt(new[] { "FW-001" }, timestamp, history);

        Assert.Equal(timestamp, history["FW-001"].LastRemediationAttemptUtc);
        Assert.Single(history["FW-001"].RemediationCycles);
        Assert.Equal(timestamp, history["FW-001"].RemediationCycles[0].AttemptedUtc);
        Assert.Null(history["FW-001"].RemediationCycles[0].VerifiedFixedUtc);
        Assert.False(history["FW-001"].RemediationCycles[0].IsClosed);
    }

    [Fact]
    public void MarkRemediationAttempt_UnknownRuleId_IsIgnored()
    {
        var history = _recorder.MarkRemediationAttempt(new[] { "UNKNOWN-001" }, DateTime.UtcNow, new Dictionary<string, RuleMemoryEntry>());

        Assert.Empty(history);
    }

    [Fact]
    public void Record_MultipleFindingsSameRuleId_RecordsOneSnapshotWithMaxSeverity()
    {
        var now = DateTime.UtcNow;
        var result = CreateResult(new[]
        {
            ("FW-001", Severity.Medium),
            ("FW-001", Severity.Critical),
            ("FW-001", Severity.High)
        }, now);

        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());

        var entry = history["FW-001"];
        Assert.Single(entry.SeverityHistory);
        Assert.Equal(Severity.Critical, entry.LastSeverity);
        Assert.Equal(RuleStatusTrend.New, entry.Trend);
    }

    [Fact]
    public void Record_MultipleFindingsSameRuleIdAcrossAudits_ComputesTrendCorrectly()
    {
        var first = CreateResult("FW-001", Severity.Medium, DateTime.UtcNow.AddDays(-1));
        var second = CreateResult(new[]
        {
            ("FW-001", Severity.High),
            ("FW-001", Severity.Medium)
        }, DateTime.UtcNow);

        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(second, history);

        var entry = history["FW-001"];
        Assert.Equal(2, entry.SeverityHistory.Count);
        Assert.Equal(RuleStatusTrend.Worsening, entry.Trend);
    }

    [Fact]
    public void MarkVerifiedFixed_CreatesOpenRemediationCycle()
    {
        var result = CreateResult("FW-001", Severity.High);
        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());
        var timestamp = new DateTime(2026, 6, 18, 12, 0, 0, DateTimeKind.Utc);

        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, timestamp, history);

        var entry = history["FW-001"];
        Assert.Single(entry.RemediationCycles);
        Assert.Equal(timestamp, entry.RemediationCycles[0].VerifiedFixedUtc);
        Assert.Null(entry.RemediationCycles[0].ReturnedUtc);
        Assert.False(entry.RemediationCycles[0].IsClosed);
    }

    [Fact]
    public void MarkVerifiedFixed_UsesPendingAttemptCycle()
    {
        var result = CreateResult("FW-001", Severity.High);
        var history = _recorder.Record(result, new Dictionary<string, RuleMemoryEntry>());
        var attemptedUtc = new DateTime(2026, 6, 18, 10, 0, 0, DateTimeKind.Utc);
        var verifiedUtc = new DateTime(2026, 6, 18, 12, 0, 0, DateTimeKind.Utc);

        history = _recorder.MarkRemediationAttempt(new[] { "FW-001" }, attemptedUtc, history);
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, verifiedUtc, history);

        var entry = history["FW-001"];
        Assert.Single(entry.RemediationCycles);
        Assert.Equal(attemptedUtc, entry.RemediationCycles[0].AttemptedUtc);
        Assert.Equal(verifiedUtc, entry.RemediationCycles[0].VerifiedFixedUtc);
        Assert.False(entry.RemediationCycles[0].IsClosed);
    }

    [Fact]
    public void Record_ReturnedAfterFix_ClosesRemediationCycle()
    {
        var now = DateTime.UtcNow;
        var first = CreateResult("FW-001", Severity.High, now.AddDays(-2));
        var history = _recorder.Record(first, new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now.AddDays(-1), history);

        var returned = CreateResult("FW-001", Severity.High, now);
        history = _recorder.Record(returned, history);

        var entry = history["FW-001"];
        Assert.Single(entry.RemediationCycles);
        Assert.True(entry.RemediationCycles[0].IsClosed);
        Assert.Equal(now, entry.RemediationCycles[0].ReturnedUtc);
    }

    [Fact]
    public void Record_MultipleReturns_CreatesMultipleCycles()
    {
        var now = DateTime.UtcNow;
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-10)), new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now.AddDays(-9), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-8)), history);
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now.AddDays(-7), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-6)), history);
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now.AddDays(-5), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now), history);

        var entry = history["FW-001"];
        Assert.Equal(3, entry.RemediationCycles.Count);
        Assert.Equal(3, entry.RemediationCycles.Count(c => c.IsClosed));
        Assert.DoesNotContain(entry.RemediationCycles, c => !c.IsClosed);
    }

    [Fact]
    public void Record_LegacyClosedCycleMatchingTimestamp_ClearsLastVerifiedFixedUtc()
    {
        var now = DateTime.UtcNow;
        var verifiedUtc = now.AddDays(-5);
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-10)), new Dictionary<string, RuleMemoryEntry>());
        history = new Dictionary<string, RuleMemoryEntry>(history, StringComparer.OrdinalIgnoreCase)
        {
            ["FW-001"] = history["FW-001"] with
            {
                LastVerifiedFixedUtc = verifiedUtc,
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        AttemptedUtc = now.AddDays(-6),
                        VerifiedFixedUtc = verifiedUtc,
                        ReturnedUtc = now.AddDays(-4),
                        CycleNumber = 1
                    }
                }
            }
        };

        history = _recorder.Record(CreateResult("FW-001", Severity.High, now), history);

        var entry = history["FW-001"];
        Assert.Null(entry.LastVerifiedFixedUtc);
        Assert.Single(entry.RemediationCycles);
    }

    [Fact]
    public void Record_NoVerifiedFixed_DoesNotCreateCycle()
    {
        var now = DateTime.UtcNow;
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-1)), new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now), history);

        var entry = history["FW-001"];
        Assert.Empty(entry.RemediationCycles);
    }

    [Fact]
    public void Record_SingleFixAndRepeatedReturns_DoesNotCreateDuplicateCycles()
    {
        var now = DateTime.UtcNow;
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-10)), new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now.AddDays(-8), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-6)), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-4)), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-2)), history);
        history = _recorder.Record(CreateResult("FW-001", Severity.High, now), history);

        var entry = history["FW-001"];
        Assert.Single(entry.RemediationCycles);
        Assert.True(entry.RemediationCycles[0].IsClosed);
        Assert.Null(entry.LastVerifiedFixedUtc);
    }

    [Fact]
    public void MarkVerifiedFixed_DoubleCall_PreservesFirstAttemptTimestamp()
    {
        var now = DateTime.UtcNow;
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-2)), new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.MarkRemediationAttempt(new[] { "FW-001" }, now.AddDays(-1), history);

        var firstVerified = now.AddHours(-2);
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, firstVerified, history);

        var secondVerified = now;
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, secondVerified, history);

        var entry = history["FW-001"];
        Assert.Single(entry.RemediationCycles);
        Assert.Equal(now.AddDays(-1), entry.RemediationCycles[0].AttemptedUtc);
        Assert.Equal(secondVerified, entry.RemediationCycles[0].VerifiedFixedUtc);
    }

    [Fact]
    public void MarkVerifiedFixed_IdempotentSameTimestamp_DoesNotOverwrite()
    {
        var now = DateTime.UtcNow;
        var history = _recorder.Record(CreateResult("FW-001", Severity.High, now.AddDays(-2)), new Dictionary<string, RuleMemoryEntry>());
        history = _recorder.MarkRemediationAttempt(new[] { "FW-001" }, now.AddDays(-1), history);

        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now, history);
        var firstEntry = history["FW-001"];
        history = _recorder.MarkVerifiedFixed(new[] { "FW-001" }, now, history);
        var secondEntry = history["FW-001"];

        Assert.Equal(firstEntry.RemediationCycles[0].AttemptedUtc, secondEntry.RemediationCycles[0].AttemptedUtc);
        Assert.Equal(firstEntry.RemediationCycles[0].VerifiedFixedUtc, secondEntry.RemediationCycles[0].VerifiedFixedUtc);
    }

    private static AgentResult CreateResult(string ruleId, Severity severity, DateTime? utc = null)
    {
        return CreateResult(new[] { (ruleId, severity) }, utc);
    }

    private static AgentResult CreateResult((string RuleId, Severity Severity)[] findings, DateTime? utc = null)
    {
        var timestamp = utc ?? DateTime.UtcNow;
        var agentFindings = findings.Select(f => new Finding
        {
            RuleId = f.RuleId,
            Category = f.RuleId.Split('-')[0] switch
            {
                "FW" => "Firewall",
                "SSH" => "SSH",
                "PORT" => "Port",
                _ => "Test"
            },
            Severity = f.Severity,
            SourceHost = "localhost",
            Target = "target",
            ShortDescription = $"Finding {f.RuleId}",
            Details = "Details",
            TimeRangeStart = timestamp,
            TimeRangeEnd = timestamp
        }).ToList();

        return new AgentResult
        {
            AgentFindings = agentFindings,
            UtcTimestamp = timestamp
        };
    }
}
