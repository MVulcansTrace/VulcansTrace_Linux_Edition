using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class TimelineViewModelTraceMapTests
{
    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
    public void GroupModeChange_RaisesRowHeaderLabelChanged()
    {
        var vm = new TimelineViewModel();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.GroupMode = TimelineGroupMode.Host;

        Assert.Contains(nameof(TimelineViewModel.RowHeaderLabel), changed);
        Assert.Equal("Hosts", vm.RowHeaderLabel);
    }

    [AvaloniaFact]
    public void LoadAnalysisResult_NullResult_ClearsEverything()
    {
        var vm = new TimelineViewModel();
        vm.LoadAnalysisResult(null);

        Assert.Empty(vm.TimelineEntries);
        Assert.Empty(vm.TimelineEdges);
        Assert.Empty(vm.Categories);
        Assert.Equal(0, vm.CanvasHeight);
    }

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaFact]
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

    [AvaloniaTheory]
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

    [AvaloniaFact]
    public void SelectedFindingId_SetToValidId_SelectedEntryMatches()
    {
        var vm = new TimelineViewModel();
        var baseTime = DateTime.UtcNow;
        var finding = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected",
            Details = "Details"
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { finding } });
        vm.SelectedFindingId = finding.Id;

        Assert.NotNull(vm.SelectedEntry);
        Assert.Equal(finding.Id, vm.SelectedEntry.FindingId);
        Assert.Equal(FindingCategories.Beaconing, vm.SelectedEntry.Category);
        Assert.Equal("192.168.1.10", vm.SelectedEntry.SourceHost);
        Assert.Equal("10.0.0.5:443", vm.SelectedEntry.Target);
        Assert.Equal("Beaconing detected", vm.SelectedEntry.Description);
        Assert.True(vm.IsFindingSelected);
    }

    [AvaloniaFact]
    public void SelectedFindingId_Clear_SelectedEntryIsNull()
    {
        var vm = new TimelineViewModel();
        var finding = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "host-a",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
            ShortDescription = "A"
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { finding } });
        vm.SelectedFindingId = finding.Id;
        Assert.NotNull(vm.SelectedEntry);

        vm.SelectedFindingId = Guid.Empty;

        Assert.Null(vm.SelectedEntry);
        Assert.False(vm.IsFindingSelected);
    }

    [AvaloniaFact]
    public void LoadAnalysisResult_ClearsSelectedEntry()
    {
        var vm = new TimelineViewModel();
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "host-a",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
            ShortDescription = "A"
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1 } });
        vm.SelectedFindingId = f1.Id;
        Assert.NotNull(vm.SelectedEntry);

        vm.LoadAnalysisResult(new AnalysisResult { Findings = Array.Empty<Finding>() });

        Assert.Null(vm.SelectedEntry);
        Assert.Equal(Guid.Empty, vm.SelectedFindingId);
    }

    [AvaloniaFact]
    public void SelectedFindingId_Change_Fires_After_ConnectedFindings_Updated()
    {
        // Regression guard: the view re-renders on the SelectedFindingId change, so
        // ConnectedFindingIds must already reflect the new selection at that moment,
        // otherwise marker/edge dimming renders one selection stale.
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow.AddMinutes(10), TimeRangeEnd = DateTime.UtcNow.AddMinutes(15), ShortDescription = "B" };
        var edges = new List<CorrelationEdge> { new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "A→B", CorrelationConfidence.High) };
        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1, f2 } }, edges);

        HashSet<Guid>? snapshotAtChange = null;
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(TimelineViewModel.SelectedFindingId))
            {
                snapshotAtChange = new HashSet<Guid>(vm.ConnectedFindingIds);
            }
        };

        vm.SelectedFindingId = f1.Id;

        Assert.NotNull(snapshotAtChange);
        Assert.Contains(f1.Id, snapshotAtChange!);
        Assert.Contains(f2.Id, snapshotAtChange!);
    }

    [AvaloniaFact]
    public void SelectedFindingId_StaleId_HidesDetailCard()
    {
        // A non-empty id with no matching entry must not leave the detail card visible.
        var vm = new TimelineViewModel();
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = DateTime.UtcNow, TimeRangeEnd = DateTime.UtcNow.AddMinutes(5), ShortDescription = "A" };
        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { f1 } });

        vm.SelectedFindingId = Guid.NewGuid(); // an id with no matching timeline entry

        Assert.Null(vm.SelectedEntry);
        Assert.False(vm.IsFindingSelected);
    }

    [AvaloniaFact]
    public void LoadAnalysisResult_SingleRow_ReservesStableOverlayRoom()
    {
        var vm = new TimelineViewModel();
        var finding = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "host-a",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
            ShortDescription = "A single-row timeline should still have room for the selected finding overlay."
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = new[] { finding } });
        var heightBeforeSelection = vm.CanvasHeight;

        vm.SelectedFindingId = finding.Id;

        Assert.Equal(vm.MinimumInteractiveCanvasHeight, heightBeforeSelection);
        Assert.Equal(heightBeforeSelection, vm.CanvasHeight);
    }

    [AvaloniaFact]
    public void FormattedTimeRange_NormalizesBeforeFormatting()
    {
        // DateTimeKind-agnostic expectations (all Utc): locks the normalized-comparison
        // refactor so mixed-Kind inputs no longer misclassify the single-vs-range branch.
        var baseUtc = new DateTime(2026, 6, 30, 12, 0, 0, DateTimeKind.Utc);

        Assert.Equal("No time data", new TimelineEntry { StartTime = DateTime.MinValue, EndTime = baseUtc }.FormattedTimeRange);
        Assert.Equal("2026-06-30 12:00:00 UTC", new TimelineEntry { StartTime = baseUtc, EndTime = baseUtc }.FormattedTimeRange);
        Assert.Equal("2026-06-30 12:00:00 – 12:05:00 UTC", new TimelineEntry { StartTime = baseUtc, EndTime = baseUtc.AddMinutes(5) }.FormattedTimeRange);
        Assert.Equal("2026-06-30 12:00:00 UTC – 2026-07-01 09:00:00 UTC", new TimelineEntry { StartTime = baseUtc, EndTime = baseUtc.AddDays(1).AddHours(-3) }.FormattedTimeRange);
    }

    [AvaloniaFact]
    public void LoadAnalysisResult_SubSecondSpan_KeepsRealAxisWindowAndSpreadsMarkers()
    {
        // Regression: point-in-time agent audits span ~10 ms. The axis window must
        // stay the real range so markers keep their full 0-1 spread.
        var vm = new TimelineViewModel();
        var baseUtc = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);
        var findings = new[]
        {
            new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = baseUtc, TimeRangeEnd = baseUtc, ShortDescription = "first" },
            new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = baseUtc.AddMilliseconds(3), TimeRangeEnd = baseUtc.AddMilliseconds(3), ShortDescription = "middle" },
            new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = baseUtc.AddMilliseconds(10), TimeRangeEnd = baseUtc.AddMilliseconds(10), ShortDescription = "last" },
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = findings });

        Assert.Equal(baseUtc, vm.MinTime);
        Assert.Equal(baseUtc.AddMilliseconds(10), vm.MaxTime);
        Assert.Equal(vm.MinTime, vm.AxisMinTime);
        Assert.Equal(vm.MaxTime, vm.AxisMaxTime);

        Assert.Equal(0, vm.TimelineEntries[0].StartPosition, 6);
        Assert.Equal(0.3, vm.TimelineEntries[1].StartPosition, 6);
        Assert.Equal(1, vm.TimelineEntries[2].StartPosition, 6);
    }

    [AvaloniaFact]
    public void LoadAnalysisResult_SingleInstant_PadsAxisWindowAndCentersMarkers()
    {
        // Every finding at the same instant: the axis needs a synthetic window or
        // the span is zero and all markers pile on the left edge.
        var vm = new TimelineViewModel();
        var baseUtc = new DateTime(2026, 7, 11, 20, 7, 4, DateTimeKind.Utc);
        var findings = new[]
        {
            new Finding { Category = FindingCategories.Beaconing, SourceHost = "host-a", TimeRangeStart = baseUtc, TimeRangeEnd = baseUtc, ShortDescription = "a" },
            new Finding { Category = FindingCategories.PortScan, SourceHost = "host-a", TimeRangeStart = baseUtc, TimeRangeEnd = baseUtc, ShortDescription = "b" },
        };

        vm.LoadAnalysisResult(new AnalysisResult { Findings = findings });

        // True range is unchanged; only the display window is padded.
        Assert.Equal(baseUtc, vm.MinTime);
        Assert.Equal(baseUtc, vm.MaxTime);
        Assert.Equal(TimeSpan.FromSeconds(1), vm.AxisMaxTime!.Value - vm.AxisMinTime!.Value);
        Assert.True(vm.AxisMinTime < baseUtc && vm.AxisMaxTime > baseUtc);
        Assert.All(vm.TimelineEntries, e => Assert.Equal(0.5, e.StartPosition, 6));
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
