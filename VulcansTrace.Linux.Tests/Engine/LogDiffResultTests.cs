using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Tests.Engine;

public class LogDiffResultTests
{
    [Fact]
    public void Summary_EmptyResult_ZeroCounts()
    {
        var result = new LogDiffResult();

        Assert.Equal(0, result.AddedCount);
        Assert.Equal(0, result.RemovedCount);
        Assert.Equal(0, result.ChangedCount);
        Assert.Equal(0, result.UnchangedCount);
        Assert.Contains("0 added", result.Summary);
    }

    [Fact]
    public void Narrative_NoDifferences_ReturnsNoDiffMessage()
    {
        var result = new LogDiffResult();

        Assert.Equal("No differences detected between the two logs.", result.Narrative);
    }

    [Fact]
    public void Narrative_AddedPatterns_UsesPluralForm()
    {
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new() { ConnectionKey = "a", State = LogDiffState.Added, BaselineCount = 0, IncidentCount = 1 }
            }
        };

        Assert.Contains("1 new traffic pattern", result.Narrative);
    }

    [Fact]
    public void Narrative_MultipleAddedPatterns_UsesPluralForm()
    {
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new() { ConnectionKey = "a", State = LogDiffState.Added, BaselineCount = 0, IncidentCount = 1 },
                new() { ConnectionKey = "b", State = LogDiffState.Added, BaselineCount = 0, IncidentCount = 1 }
            }
        };

        Assert.Contains("2 new traffic patterns", result.Narrative);
    }

    [Fact]
    public void Narrative_RemovedPatterns_IncludesRemovedPhrase()
    {
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new() { ConnectionKey = "a", State = LogDiffState.Removed, BaselineCount = 1, IncidentCount = 0 }
            }
        };

        Assert.Contains("1 disappeared traffic pattern", result.Narrative);
    }

    [Fact]
    public void Narrative_ChangedPatterns_IncludesChangedPhrase()
    {
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new() { ConnectionKey = "a", State = LogDiffState.Changed, BaselineCount = 1, IncidentCount = 5 }
            }
        };

        Assert.Contains("1 changed traffic pattern", result.Narrative);
    }

    [Fact]
    public void Narrative_FindingsAdded_IncludesFindingPhrase()
    {
        var result = new LogDiffResult
        {
            Findings = new List<DiffFinding>
            {
                new() { State = LogDiffState.Added, Finding = CreateDummyFinding() }
            }
        };

        Assert.Contains("1 new finding", result.Narrative);
    }

    [Fact]
    public void Narrative_MultipleStates_JoinsWithCommas()
    {
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new() { ConnectionKey = "a", State = LogDiffState.Added, BaselineCount = 0, IncidentCount = 1 },
                new() { ConnectionKey = "b", State = LogDiffState.Removed, BaselineCount = 1, IncidentCount = 0 }
            }
        };

        var narrative = result.Narrative;
        Assert.Contains(",", narrative);
        Assert.EndsWith(".", narrative);
    }

    private static VulcansTrace.Linux.Core.Finding CreateDummyFinding()
    {
        return new VulcansTrace.Linux.Core.Finding
        {
            Category = VulcansTrace.Linux.Core.FindingCategories.PortScan,
            Severity = VulcansTrace.Linux.Core.Severity.High,
            SourceHost = "10.0.0.1",
            Target = "192.168.1.1:80",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
            ShortDescription = "Test",
            Details = "Test details"
        };
    }
}
