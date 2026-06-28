using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for timeline visualization of security events, extended to support
/// Trace Map correlation edges and host-based grouping.
/// </summary>
public class TimelineViewModel : ViewModelBase
{
    private const double DefaultRowHeight = 22;
    private const double DefaultRowGap = 8;
    private const double DefaultTopPadding = 6;

    private AnalysisResult? _analysisResult;
    private double _canvasHeight;
    private string _timeRangeLabel = "No timeline data.";
    private TimelineGroupMode _groupMode = TimelineGroupMode.Category;
    private bool _isTraceMapEnabled;
    private Guid _selectedFindingId;
    private string _selectedChainNarrative = string.Empty;
    private IReadOnlyList<CorrelationEdge> _correlationEdges = Array.Empty<CorrelationEdge>();
    private bool _hasLoadedAnalysis;

    public ObservableCollection<TimelineEntry> TimelineEntries { get; set; } = new();
    public ObservableCollection<TimelineEdge> TimelineEdges { get; set; } = new();

    /// <summary>
    /// True when the timeline has entries to display.
    /// </summary>
    public bool HasTimelineData => TimelineEntries.Count > 0;

    /// <summary>
    /// True when an analysis or audit result has been loaded into the timeline.
    /// </summary>
    public bool HasLoadedAnalysis
    {
        get => _hasLoadedAnalysis;
        private set
        {
            if (SetField(ref _hasLoadedAnalysis, value))
            {
                RaiseEmptyStateText();
            }
        }
    }

    /// <summary>Gets the headline shown when the timeline has no entries.</summary>
    public string EmptyStateHeadline => HasLoadedAnalysis ? "No timeline events in this result" : "No timeline yet";

    /// <summary>Gets the description shown when the timeline has no entries.</summary>
    public string EmptyStateDescription => HasLoadedAnalysis
        ? "The last run completed, but no findings had usable time ranges to place on the trace map."
        : "Paste a firewall log and click Analyze to build a trace map.";

    /// <summary>Gets or sets the command invoked by the empty-state action button.</summary>
    public ICommand? EmptyStateActionCommand { get; set; }

    /// <summary>Gets or sets the text of the empty-state action button.</summary>
    public string EmptyStateActionText { get; set; } = "Analyze";

    public DateTime? MinTime { get; set; }
    public DateTime? MaxTime { get; set; }

    /// <summary>
    /// IDs of findings connected to <see cref="SelectedFindingId"/> via correlation edges.
    /// Includes the selected finding itself.
    /// </summary>
    public HashSet<Guid> ConnectedFindingIds { get; } = new();

    /// <summary>
    /// Row labels for the Y-axis. When <see cref="GroupMode"/> is <see cref="TimelineGroupMode.Category"/>,
    /// these are finding categories. When <see cref="GroupMode"/> is <see cref="TimelineGroupMode.Host"/>,
    /// these are distinct source hosts.
    /// </summary>
    public ObservableCollection<string> Categories { get; set; } = new();

    public double RowHeight => DefaultRowHeight;
    public double RowGap => DefaultRowGap;
    public double TopPadding => DefaultTopPadding;

    public double CanvasHeight
    {
        get => _canvasHeight;
        private set => SetField(ref _canvasHeight, value);
    }

    public string TimeRangeLabel
    {
        get => _timeRangeLabel;
        private set => SetField(ref _timeRangeLabel, value);
    }

    /// <summary>
    /// Determines how the Y-axis is grouped.
    /// </summary>
    public TimelineGroupMode GroupMode
    {
        get => _groupMode;
        set
        {
            if (SetField(ref _groupMode, value))
            {
                OnPropertyChanged(nameof(RowHeaderLabel));
                if (_analysisResult != null)
                {
                    GenerateTimelineVisualization(_analysisResult);
                }
            }
        }
    }

    /// <summary>
    /// When true, correlation edges are rendered on the timeline canvas (Trace Map mode).
    /// </summary>
    public bool IsTraceMapEnabled
    {
        get => _isTraceMapEnabled;
        set
        {
            if (SetField(ref _isTraceMapEnabled, value))
            {
                OnPropertyChanged(nameof(RowHeaderLabel));
                OnPropertyChanged(nameof(IsNarrativeVisible));
            }
        }
    }

    /// <summary>
    /// True when the narrative panel should be shown (Trace Map is on and a finding is selected).
    /// </summary>
    public bool IsNarrativeVisible => _isTraceMapEnabled && _selectedFindingId != Guid.Empty;

    /// <summary>
    /// Header text for the Y-axis label column.
    /// </summary>
    public string RowHeaderLabel => _groupMode == TimelineGroupMode.Host ? "Hosts" : "Categories";

    /// <summary>
    /// The finding currently selected by the user (clicked on the timeline canvas).
    /// </summary>
    public Guid SelectedFindingId
    {
        get => _selectedFindingId;
        set
        {
            if (SetField(ref _selectedFindingId, value))
            {
                UpdateConnectedFindings();
                OnPropertyChanged(nameof(IsNarrativeVisible));
            }
        }
    }

    /// <summary>
    /// Narrative text describing the attack chain for the selected finding.
    /// </summary>
    public string SelectedChainNarrative
    {
        get => _selectedChainNarrative;
        private set => SetField(ref _selectedChainNarrative, value);
    }

    /// <summary>
    /// True when there are too many edges to render interactively.
    /// </summary>
    public bool IsEdgeRenderingSuppressed => _correlationEdges.Count > 100;

    /// <summary>
    /// Message shown when edge rendering is suppressed for performance.
    /// </summary>
    public string SuppressionMessage =>
        IsEdgeRenderingSuppressed
            ? $"{_correlationEdges.Count} correlations detected — too many to display interactively. Export the evidence bundle for the full Trace Map."
            : string.Empty;

    public TimelineViewModel()
    {
        TimelineEntries.CollectionChanged += (_, _) => OnPropertyChanged(nameof(HasTimelineData));
    }

    /// <summary>
    /// Loads an analysis result without correlation edges (legacy timeline mode).
    /// </summary>
    public void LoadAnalysisResult(AnalysisResult? result)
    {
        LoadAnalysisResult(result, Array.Empty<CorrelationEdge>());
    }

    /// <summary>
    /// Loads an analysis result with optional correlation edges (Trace Map mode).
    /// </summary>
    public void LoadAnalysisResult(AnalysisResult? result, IReadOnlyList<CorrelationEdge> edges)
    {
        _analysisResult = result;
        HasLoadedAnalysis = result != null;
        _correlationEdges = edges ?? Array.Empty<CorrelationEdge>();
        OnPropertyChanged(nameof(IsEdgeRenderingSuppressed));
        OnPropertyChanged(nameof(SuppressionMessage));

        TimelineEntries.Clear();
        TimelineEdges.Clear();
        Categories.Clear();
        ClearSelection();

        if (result == null || !result.Findings.Any())
        {
            MinTime = null;
            MaxTime = null;
            CanvasHeight = 0;
            TimeRangeLabel = "No timeline data.";
            return;
        }

        GenerateTimelineVisualization(result);
    }

    private void GenerateTimelineVisualization(AnalysisResult result)
    {
        TimelineEntries.Clear();
        TimelineEdges.Clear();
        Categories.Clear();
        ClearSelection();

        // Determine the overall time range
        var allTimes = result.Findings
            .SelectMany(f => new[] { f.TimeRangeStart, f.TimeRangeEnd })
            .Where(t => t != DateTime.MinValue);

        if (!allTimes.Any())
        {
            MinTime = null;
            MaxTime = null;
            CanvasHeight = 0;
            TimeRangeLabel = "No timeline data.";
            return;
        }

        MinTime = allTimes.Min();
        MaxTime = allTimes.Max();
        TimeRangeLabel = $"Time range: {MinTime:O} – {MaxTime:O}";

        // Build row labels based on grouping mode
        if (_groupMode == TimelineGroupMode.Host)
        {
            var hosts = result.Findings
                .Select(f => f.SourceHost)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(h => h);
            foreach (var host in hosts)
            {
                Categories.Add(host);
            }
        }
        else
        {
            var categories = result.Findings
                .GroupBy(f => f.Category)
                .Select(g => g.Key)
                .OrderBy(c => c);
            foreach (var category in categories)
            {
                Categories.Add(category);
            }
        }

        // Create timeline entries for each finding (CalculateEntryPositions handles DateTime.MinValue)
        foreach (var finding in result.Findings)
        {
            TimelineEntries.Add(new TimelineEntry
            {
                Category = finding.Category,
                SourceHost = finding.SourceHost,
                StartTime = finding.TimeRangeStart,
                EndTime = finding.TimeRangeEnd,
                Description = finding.ShortDescription,
                Severity = finding.Severity,
                FindingId = finding.Id
            });
        }

        CalculateEntryPositions();
        CalculateEdgePositions();
    }

    private void CalculateEntryPositions()
    {
        if (!MinTime.HasValue || !MaxTime.HasValue)
        {
            CanvasHeight = 0;
            return;
        }

        var totalSeconds = (MaxTime.Value - MinTime.Value).TotalSeconds;
        if (totalSeconds <= 0)
        {
            totalSeconds = 1;
        }

        var rowIndex = Categories
            .Select((label, index) => new { label, index })
            .ToDictionary(x => x.label, x => x.index, StringComparer.OrdinalIgnoreCase);

        foreach (var entry in TimelineEntries)
        {
            var start = entry.StartTime == DateTime.MinValue ? MinTime.Value : entry.StartTime;
            var end = entry.EndTime == DateTime.MinValue ? start : entry.EndTime;
            if (end < start)
            {
                end = start;
            }

            var startOffset = (start - MinTime.Value).TotalSeconds / totalSeconds;
            var endOffset = (end - MinTime.Value).TotalSeconds / totalSeconds;

            entry.StartPosition = Clamp01(startOffset);
            entry.EndPosition = Math.Max(entry.StartPosition, Clamp01(endOffset));

            var rowKey = _groupMode == TimelineGroupMode.Host ? entry.SourceHost : entry.Category;
            if (rowIndex.TryGetValue(rowKey, out var row))
            {
                entry.TopPosition = TopPadding + row * (RowHeight + RowGap);
            }
        }

        CanvasHeight = Categories.Count == 0
            ? 0
            : TopPadding + (Categories.Count * RowHeight) + ((Categories.Count - 1) * RowGap) + TopPadding;
    }

    private void CalculateEdgePositions()
    {
        TimelineEdges.Clear();

        if (_correlationEdges.Count == 0 || TimelineEntries.Count == 0)
        {
            return;
        }

        // Build a lookup from FindingId -> TimelineEntry (deduplicated — first wins)
        var entryById = TimelineEntries
            .Where(e => e.FindingId != Guid.Empty)
            .DistinctBy(e => e.FindingId)
            .ToDictionary(e => e.FindingId);

        foreach (var edge in _correlationEdges)
        {
            if (!entryById.TryGetValue(edge.FromFindingId, out var fromEntry))
                continue;
            if (!entryById.TryGetValue(edge.ToFindingId, out var toEntry))
                continue;

            TimelineEdges.Add(new TimelineEdge
            {
                FromFindingId = edge.FromFindingId,
                ToFindingId = edge.ToFindingId,
                FromStartPosition = fromEntry.StartPosition,
                FromEndPosition = fromEntry.EndPosition,
                FromTopPosition = fromEntry.TopPosition,
                ToStartPosition = toEntry.StartPosition,
                ToEndPosition = toEntry.EndPosition,
                ToTopPosition = toEntry.TopPosition,
                CorrelationType = edge.CorrelationType,
                Narrative = edge.Narrative
            });
        }
    }

    private void UpdateConnectedFindings()
    {
        ConnectedFindingIds.Clear();
        SelectedChainNarrative = string.Empty;

        if (_selectedFindingId == Guid.Empty)
        {
            return;
        }

        ConnectedFindingIds.Add(_selectedFindingId);

        if (_correlationEdges.Count == 0)
        {
            SelectedChainNarrative = "Selected finding has no correlations.";
            return;
        }

        // Build adjacency list
        var adjacency = new Dictionary<Guid, List<CorrelationEdge>>();
        foreach (var edge in _correlationEdges)
        {
            if (!adjacency.ContainsKey(edge.FromFindingId))
                adjacency[edge.FromFindingId] = new List<CorrelationEdge>();
            if (!adjacency.ContainsKey(edge.ToFindingId))
                adjacency[edge.ToFindingId] = new List<CorrelationEdge>();
            adjacency[edge.FromFindingId].Add(edge);
            adjacency[edge.ToFindingId].Add(edge);
        }

        // Walk the graph (undirected for highlighting)
        var queue = new Queue<Guid>();
        queue.Enqueue(_selectedFindingId);
        var visited = new HashSet<Guid> { _selectedFindingId };
        var narratives = new List<string>();

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!adjacency.TryGetValue(current, out var edges))
                continue;

            foreach (var edge in edges)
            {
                var neighbor = edge.FromFindingId == current ? edge.ToFindingId : edge.FromFindingId;
                if (!visited.Contains(neighbor))
                {
                    visited.Add(neighbor);
                    ConnectedFindingIds.Add(neighbor);
                    queue.Enqueue(neighbor);
                }

                // Collect unique narratives (only once per edge)
                if (current == edge.FromFindingId && !narratives.Contains(edge.Narrative))
                {
                    narratives.Add(edge.Narrative);
                }
            }
        }

        SelectedChainNarrative = narratives.Count > 0
            ? string.Join("\n", narratives)
            : "Selected finding has no correlations.";
    }

    private void ClearSelection()
    {
        SelectedFindingId = Guid.Empty;
        ConnectedFindingIds.Clear();
        SelectedChainNarrative = string.Empty;
        OnPropertyChanged(nameof(IsNarrativeVisible));
    }

    private void RaiseEmptyStateText()
    {
        OnPropertyChanged(nameof(EmptyStateHeadline));
        OnPropertyChanged(nameof(EmptyStateDescription));
    }

    private static double Clamp01(double value)
    {
        if (value < 0) return 0;
        if (value > 1) return 1;
        return value;
    }
}

/// <summary>
/// Represents a single entry in the timeline
/// </summary>
public class TimelineEntry
{
    public string Category { get; set; } = string.Empty;
    public string SourceHost { get; set; } = string.Empty;
    public Guid FindingId { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }

    public double StartPosition { get; set; } // Position in the timeline (0-1)
    public double EndPosition { get; set; }   // Position in the timeline (0-1)
    public double TopPosition { get; set; }   // Vertical position for the category row
}
