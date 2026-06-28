using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class TimelineViewModelTraceMapTests
{
    [Fact]
    public void LoadAnalysisResult_CategoryGrouping_DefaultBehavior()
    {
        var vm = new TimelineViewModel();
        var result = CreateAnalysisResult(new[]
        {
            ("PortScan", "host-a"),
            ("Beaconing", "host-b"),
        });

        vm.LoadAnalysisResult(result);

        Assert.Equal(TimelineGroupMode.Category, vm.GroupMode);
        Assert.Equal(2, vm.Categories.Count);
        Assert.Contains("Beaconing", vm.Categories);
        Assert.Contains("PortScan", vm.Categories);
        Assert.Equal(2, vm.TimelineEntries.Count);
        Assert.Empty(vm.TimelineEdges);
    }

    [Fact]
    public void LoadAnalysisResult_HostGrouping_CategoriesAreHosts()
    {
        var vm = new TimelineViewModel { GroupMode = TimelineGroupMode.Host };
        var result = CreateAnalysisResult(new[]
        {
            ("PortScan", "192.168.1.10"),
            ("Beaconing", "192.168.1.20"),
            ("LateralMovement", "192.168.1.10"),
        });

        vm.LoadAnalysisResult(result);

        Assert.Equal(2, vm.Categories.Count); // Two distinct hosts
        Assert.Contains("192.168.1.10", vm.Categories);
        Assert.Contains("192.168.1.20", vm.Categories);
    }

    [Fact]
    public void LoadAnalysisResult_HostGrouping_EntriesHaveCorrectTopPosition()
    {
        var vm = new TimelineViewModel { GroupMode = TimelineGroupMode.Host };
        var result = CreateAnalysisResult(new[]
        {
            ("PortScan", "10.0.0.1"),
            ("Beaconing", "10.0.0.2"),
        });

        vm.LoadAnalysisResult(result);

        // Hosts are sorted alphabetically: 10.0.0.1 = row 0, 10.0.0.2 = row 1
        var entry1 = vm.TimelineEntries.Single(e => e.SourceHost == "10.0.0.1");
        var entry2 = vm.TimelineEntries.Single(e => e.SourceHost == "10.0.0.2");

        Assert.Equal(vm.TopPadding + 0 * (vm.RowHeight + vm.RowGap), entry1.TopPosition);
        Assert.Equal(vm.TopPadding + 1 * (vm.RowHeight + vm.RowGap), entry2.TopPosition);
    }

    [Fact]
    public void LoadAnalysisResult_WithEdges_TimelineEdgesPopulated()
    {
        var vm = new TimelineViewModel { GroupMode = TimelineGroupMode.Host };
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing",
                Details = "Details"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                SourceHost = "192.168.1.100",
                Target = "internal",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "Lateral",
                Details = "Details"
            }
        };
        var result = new AnalysisResult
        {
            Findings = findings,
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(15)
        };
        var edges = new List<CorrelationEdge>
        {
            new(findings[0].Id, findings[1].Id, CorrelationType.EscalatesTo, "Beaconing → Lateral", CorrelationConfidence.High)
        };

        vm.LoadAnalysisResult(result, edges);

        Assert.Single(vm.TimelineEdges);
        var edge = vm.TimelineEdges[0];
        Assert.Equal(CorrelationType.EscalatesTo, edge.CorrelationType);
        Assert.Equal("Beaconing → Lateral", edge.Narrative);
    }

    [Fact]
    public void LoadAnalysisResult_WithEdges_EdgeCoordinatesMatchEntries()
    {
        var vm = new TimelineViewModel { GroupMode = TimelineGroupMode.Host };
        var baseTime = DateTime.UtcNow;
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Details = "Details"
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            Target = "internal",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral",
            Details = "Details"
        };
        var result = new AnalysisResult
        {
            Findings = new[] { f1, f2 },
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(15)
        };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Narrative", CorrelationConfidence.High)
        };

        vm.LoadAnalysisResult(result, edges);

        var entry1 = vm.TimelineEntries.Single(e => e.FindingId == f1.Id);
        var entry2 = vm.TimelineEntries.Single(e => e.FindingId == f2.Id);
        var timelineEdge = vm.TimelineEdges[0];

        Assert.Equal(entry1.StartPosition, timelineEdge.FromStartPosition);
        Assert.Equal(entry1.EndPosition, timelineEdge.FromEndPosition);
        Assert.Equal(entry1.TopPosition, timelineEdge.FromTopPosition);
        Assert.Equal(entry2.StartPosition, timelineEdge.ToStartPosition);
        Assert.Equal(entry2.EndPosition, timelineEdge.ToEndPosition);
        Assert.Equal(entry2.TopPosition, timelineEdge.ToTopPosition);
    }

    [Fact]
    public void GroupModeChange_TriggersRegeneration()
    {
        var vm = new TimelineViewModel();
        var result = CreateAnalysisResult(new[]
        {
            ("PortScan", "192.168.1.10"),
            ("Beaconing", "192.168.1.20"),
        });

        vm.LoadAnalysisResult(result);
        Assert.Equal(2, vm.Categories.Count);
        Assert.Contains("PortScan", vm.Categories);

        vm.GroupMode = TimelineGroupMode.Host;

        Assert.Equal(2, vm.Categories.Count);
        Assert.Contains("192.168.1.10", vm.Categories);
        Assert.Contains("192.168.1.20", vm.Categories);
    }

    [Fact]
    public void GroupModeChange_RaisesRowHeaderLabelChanged()
    {
        var vm = new TimelineViewModel();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.GroupMode = TimelineGroupMode.Host;

        Assert.Contains(nameof(TimelineViewModel.RowHeaderLabel), changed);
        Assert.Equal("Hosts", vm.RowHeaderLabel);
    }

    [Fact]
    public void LoadAnalysisResult_NullResult_ClearsEverything()
    {
        var vm = new TimelineViewModel();
        vm.LoadAnalysisResult(null);

        Assert.Empty(vm.TimelineEntries);
        Assert.Empty(vm.TimelineEdges);
        Assert.Empty(vm.Categories);
        Assert.Equal(0, vm.CanvasHeight);
    }

    [Fact]
    public void LoadAnalysisResult_NullResult_ClearsSelectedChainState()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var edges = new List<CorrelationEdge> { new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High) };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, edges);
        vm.IsTraceMapEnabled = true;
        vm.SelectedFindingId = f1.Id;

        vm.LoadAnalysisResult(null);

        Assert.Equal(Guid.Empty, vm.SelectedFindingId);
        Assert.Empty(vm.ConnectedFindingIds);
        Assert.Equal(string.Empty, vm.SelectedChainNarrative);
        Assert.False(vm.IsNarrativeVisible);
    }

    [Fact]
    public void LoadAnalysisResult_NoTimeRanges_SetsEmptyState()
    {
        var vm = new TimelineViewModel();
        var result = new AnalysisResult
        {
            Findings = new[]
            {
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    SourceHost = "host-a",
                    TimeRangeStart = DateTime.MinValue,
                    TimeRangeEnd = DateTime.MinValue,
                    ShortDescription = "No time"
                }
            }
        };

        vm.LoadAnalysisResult(result);

        Assert.Empty(vm.TimelineEntries);
        Assert.Equal(0, vm.CanvasHeight);
        Assert.True(vm.HasLoadedAnalysis);
        Assert.Equal("No timeline events in this result", vm.EmptyStateHeadline);
        Assert.Contains("last run completed", vm.EmptyStateDescription);
    }

    [Fact]
    public void LoadAnalysisResult_NullResult_RestoresInitialTimelineEmptyState()
    {
        var vm = new TimelineViewModel();

        vm.LoadAnalysisResult(new AnalysisResult());
        Assert.True(vm.HasLoadedAnalysis);

        vm.LoadAnalysisResult(null);

        Assert.False(vm.HasLoadedAnalysis);
        Assert.Equal("No timeline yet", vm.EmptyStateHeadline);
        Assert.Contains("click Analyze", vm.EmptyStateDescription);
    }

    [Fact]
    public void SelectedFindingId_EmptySelection_ClearsConnectedIds()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var edges = new List<CorrelationEdge> { new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Edge narrative", CorrelationConfidence.High) };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, edges);
        vm.SelectedFindingId = f1.Id;
        Assert.Contains(f2.Id, vm.ConnectedFindingIds);

        vm.SelectedFindingId = Guid.Empty;
        Assert.Empty(vm.ConnectedFindingIds);
        Assert.Equal(string.Empty, vm.SelectedChainNarrative);
    }

    [Fact]
    public void SelectedFindingId_DirectConnection_FindsNeighbor()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var edges = new List<CorrelationEdge> { new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High) };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, edges);
        vm.SelectedFindingId = f1.Id;

        Assert.Equal(2, vm.ConnectedFindingIds.Count);
        Assert.Contains(f1.Id, vm.ConnectedFindingIds);
        Assert.Contains(f2.Id, vm.ConnectedFindingIds);
        Assert.Contains("A→B", vm.SelectedChainNarrative);
    }

    [Fact]
    public void SelectedFindingId_TransitiveConnection_BFSWalksChain()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var f3 = new Finding { Category = FindingCategories.C2Channel, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(20), TimeRangeEnd = DateTime.UtcNow.AddMinutes(25), ShortDescription = "C" };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High),
            new(f2.Id, f3.Id, CorrelationType.EscalatesTo, "B→C", CorrelationConfidence.High)
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2, f3 } }, edges);
        vm.SelectedFindingId = f1.Id;

        Assert.Equal(3, vm.ConnectedFindingIds.Count);
        Assert.Contains(f3.Id, vm.ConnectedFindingIds);
        Assert.Contains("A→B", vm.SelectedChainNarrative);
        Assert.Contains("B→C", vm.SelectedChainNarrative);
    }

    [Fact]
    public void SelectedFindingId_DisconnectedComponent_Isolated()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var f3 = new Finding { Category = FindingCategories.PortScan, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(20), TimeRangeEnd = DateTime.UtcNow.AddMinutes(25), ShortDescription = "C" };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High)
            // f3 is disconnected
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2, f3 } }, edges);
        vm.SelectedFindingId = f1.Id;

        Assert.Equal(2, vm.ConnectedFindingIds.Count);
        Assert.Contains(f1.Id, vm.ConnectedFindingIds);
        Assert.Contains(f2.Id, vm.ConnectedFindingIds);
        Assert.DoesNotContain(f3.Id, vm.ConnectedFindingIds);
    }

    [Fact]
    public void SelectedFindingId_SwitchesSelection_UpdatesCorrectly()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var edges = new List<CorrelationEdge> { new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High) };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, edges);

        vm.SelectedFindingId = f1.Id;
        Assert.Contains(f2.Id, vm.ConnectedFindingIds);

        vm.SelectedFindingId = f2.Id;
        Assert.Contains(f1.Id, vm.ConnectedFindingIds);
        Assert.Contains("A→B", vm.SelectedChainNarrative);
    }

    [Fact]
    public void IsEdgeRenderingSuppressed_AtThreshold_NotSuppressed()
    {
        var vm = new TimelineViewModel();
        var edges = Enumerable.Range(0, 100)
            .Select(i => new CorrelationEdge(Guid.NewGuid(), Guid.NewGuid(), CorrelationType.EscalatesTo, $"Edge {i}", CorrelationConfidence.High))
            .ToList();

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { new Finding { ShortDescription = "F" } } }, edges);

        Assert.False(vm.IsEdgeRenderingSuppressed);
        Assert.Equal(string.Empty, vm.SuppressionMessage);
    }

    [Fact]
    public void IsEdgeRenderingSuppressed_AboveThreshold_Suppressed()
    {
        var vm = new TimelineViewModel();
        var edges = Enumerable.Range(0, 101)
            .Select(i => new CorrelationEdge(Guid.NewGuid(), Guid.NewGuid(), CorrelationType.EscalatesTo, $"Edge {i}", CorrelationConfidence.High))
            .ToList();

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { new Finding { ShortDescription = "F" } } }, edges);

        Assert.True(vm.IsEdgeRenderingSuppressed);
        Assert.Contains("101 correlations detected", vm.SuppressionMessage);
        Assert.Contains("Export the evidence bundle", vm.SuppressionMessage);
    }

    [Fact]
    public void LoadAnalysisResult_EdgeCountChange_RaisesSuppressionPropertiesChanged()
    {
        var vm = new TimelineViewModel();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        var edges = Enumerable.Range(0, 101)
            .Select(i => new CorrelationEdge(Guid.NewGuid(), Guid.NewGuid(), CorrelationType.EscalatesTo, $"Edge {i}", CorrelationConfidence.High))
            .ToList();

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { new Finding { ShortDescription = "F" } } }, edges);

        Assert.Contains(nameof(TimelineViewModel.IsEdgeRenderingSuppressed), changed);
        Assert.Contains(nameof(TimelineViewModel.SuppressionMessage), changed);
    }

    [Fact]
    public void SelectedFindingId_NoCorrelations_ShowsNoCorrelationsMessage()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.PortScan, SourceHost = "host-b", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };

        // No edges — findings are on different hosts
        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, Array.Empty<CorrelationEdge>());
        vm.SelectedFindingId = f1.Id;

        Assert.Single(vm.ConnectedFindingIds); // only itself
        Assert.Contains(f1.Id, vm.ConnectedFindingIds);
        Assert.Equal("Selected finding has no correlations.", vm.SelectedChainNarrative);
    }

    [Theory]
    [InlineData(false, false, false)]  // TraceMap off, no selection
    [InlineData(true, false, false)]   // TraceMap on, no selection
    [InlineData(false, true, false)]   // TraceMap off, has selection
    [InlineData(true, true, true)]     // TraceMap on, has selection
    public void IsNarrativeVisible_RespectsTraceMapAndSelection(bool traceMapEnabled, bool hasSelection, bool expectedVisible)
    {
        var vm = new TimelineViewModel();
        var finding = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, ShortDescription = "X" };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { finding } }, Array.Empty<CorrelationEdge>());
        vm.IsTraceMapEnabled = traceMapEnabled;
        vm.SelectedFindingId = hasSelection ? finding.Id : Guid.Empty;

        Assert.Equal(expectedVisible, vm.IsNarrativeVisible);
    }

    private static AnalysisResult CreateAnalysisResult(IEnumerable<(string Category, string SourceHost)> items)
    {
        var baseTime = DateTime.UtcNow;
        var findings = items.Select((item, index) => new Finding
        {
            Category = item.Category,
            SourceHost = item.SourceHost,
            TimeRangeStart = baseTime.AddMinutes(index * 5),
            TimeRangeEnd = baseTime.AddMinutes(index * 5 + 2),
            ShortDescription = $"Finding {index}",
            Details = "Details"
        }).ToList();

        return new AnalysisResult
        {
            Findings = findings,
            TimeRangeStart = findings.Min(f => f.TimeRangeStart),
            TimeRangeEnd = findings.Max(f => f.TimeRangeEnd)
        };
    }
}
