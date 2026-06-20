using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ExplanationDepthResolverTests
{
    [Fact]
    public void Resolve_NullEntry_ReturnsStandard()
    {
        Assert.Equal(ExplanationDepth.Standard, ExplanationDepthResolver.Resolve(null));
    }

    [Fact]
    public void Resolve_SingleSnapshot_ReturnsStandard()
    {
        var entry = CreateEntry(new[] { Severity.High });

        Assert.Equal(ExplanationDepth.Standard, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_TwoStableSnapshotsNoCycles_ReturnsFamiliar()
    {
        var entry = CreateEntry(new[] { Severity.High, Severity.High });

        Assert.Equal(ExplanationDepth.Familiar, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_TwoImprovingSnapshotsNoCycles_ReturnsFamiliar()
    {
        var entry = CreateEntry(new[] { Severity.High, Severity.Medium });

        Assert.Equal(ExplanationDepth.Familiar, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_WorseningTrend_ReturnsEscalating()
    {
        var entry = CreateEntry(new[] { Severity.Medium, Severity.High });

        Assert.Equal(ExplanationDepth.Escalating, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_WorseningTrendDominatesOverRecurringCycles_ReturnsEscalating()
    {
        var entry = CreateEntry(new[] { Severity.Medium, Severity.High }, closedCycles: 5);

        Assert.Equal(ExplanationDepth.Escalating, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_TwoClosedCyclesStable_ReturnsRecurring()
    {
        var entry = CreateEntry(new[] { Severity.High, Severity.High }, closedCycles: 2);

        Assert.Equal(ExplanationDepth.Recurring, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_OneClosedCycle_ReturnsFamiliar()
    {
        var entry = CreateEntry(new[] { Severity.High, Severity.High }, closedCycles: 1);

        Assert.Equal(ExplanationDepth.Familiar, ExplanationDepthResolver.Resolve(entry));
    }

    [Fact]
    public void Resolve_OpenCyclesOnly_DoNotCountTowardRecurring()
    {
        var entry = CreateEntry(new[] { Severity.High, Severity.High }, openCycles: 3);

        Assert.Equal(ExplanationDepth.Familiar, ExplanationDepthResolver.Resolve(entry));
    }

    private static RuleMemoryEntry CreateEntry(
        Severity[] severities,
        int closedCycles = 0,
        int openCycles = 0)
    {
        var now = DateTime.UtcNow;
        var snapshots = severities
            .Select((severity, index) => new RuleSeveritySnapshot
            {
                UtcTimestamp = now.AddDays(-(severities.Length - 1 - index)),
                Severity = severity
            })
            .ToArray();

        var previous = snapshots.Length >= 2 ? snapshots[^2].Severity : snapshots[^1].Severity;
        var current = snapshots[^1].Severity;
        var trend = current > previous
            ? RuleStatusTrend.Worsening
            : current < previous
                ? RuleStatusTrend.Improving
                : RuleStatusTrend.Stable;

        var cycles = new List<RemediationCycle>();
        for (var i = 0; i < closedCycles; i++)
        {
            cycles.Add(new RemediationCycle
            {
                CycleNumber = i + 1,
                AttemptedUtc = now.AddDays(-30 * (closedCycles - i)),
                VerifiedFixedUtc = now.AddDays(-25 * (closedCycles - i)),
                ReturnedUtc = now.AddDays(-10 * (closedCycles - i))
            });
        }

        for (var i = 0; i < openCycles; i++)
        {
            cycles.Add(new RemediationCycle
            {
                CycleNumber = closedCycles + i + 1,
                AttemptedUtc = now.AddDays(-5 * (openCycles - i))
            });
        }

        return new RuleMemoryEntry
        {
            RuleId = "TEST-001",
            Category = "Test",
            FirstSeenUtc = snapshots[0].UtcTimestamp,
            LastSeenUtc = snapshots[^1].UtcTimestamp,
            SeverityHistory = snapshots,
            RemediationCycles = cycles,
            Trend = trend,
            LastSeverity = current
        };
    }
}
