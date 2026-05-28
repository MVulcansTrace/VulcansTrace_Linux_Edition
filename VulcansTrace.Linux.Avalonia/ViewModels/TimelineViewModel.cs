using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for timeline visualization of security events
/// </summary>
public class TimelineViewModel : ViewModelBase
{
    private const double DefaultRowHeight = 22;
    private const double DefaultRowGap = 8;
    private const double DefaultTopPadding = 6;

    private AnalysisResult? _analysisResult;
    private double _canvasHeight;
    private string _timeRangeLabel = "No timeline data.";

    public ObservableCollection<TimelineEntry> TimelineEntries { get; set; } = new();
    public DateTime? MinTime { get; set; }
    public DateTime? MaxTime { get; set; }
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

    public TimelineViewModel()
    {
    }

    public void LoadAnalysisResult(AnalysisResult? result)
    {
        _analysisResult = result;

        TimelineEntries.Clear();
        Categories.Clear();

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

        // Group findings by category
        var findingsByCategory = result.Findings
            .GroupBy(f => f.Category)
            .ToList();

        // Add categories to the observable collection
        foreach (var category in findingsByCategory.Select(g => g.Key).OrderBy(c => c))
        {
            Categories.Add(category);
        }

        // Create timeline entries for each finding
        foreach (var finding in result.Findings)
        {
            if (finding.TimeRangeStart != DateTime.MinValue && finding.TimeRangeEnd != DateTime.MinValue)
            {
                TimelineEntries.Add(new TimelineEntry
                {
                    Category = finding.Category,
                    StartTime = finding.TimeRangeStart,
                    EndTime = finding.TimeRangeEnd,
                    Description = finding.ShortDescription,
                    Severity = finding.Severity
                });
            }
        }

        CalculateEntryPositions();
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

        var categoryIndex = Categories
            .Select((category, index) => new { category, index })
            .ToDictionary(x => x.category, x => x.index, StringComparer.OrdinalIgnoreCase);

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

            if (categoryIndex.TryGetValue(entry.Category, out var row))
            {
                entry.TopPosition = TopPadding + row * (RowHeight + RowGap);
            }
        }

        CanvasHeight = Categories.Count == 0
            ? 0
            : TopPadding + (Categories.Count * RowHeight) + ((Categories.Count - 1) * RowGap) + TopPadding;
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
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }

    public double StartPosition { get; set; } // Position in the timeline (0-1)
    public double EndPosition { get; set; }   // Position in the timeline (0-1)
    public double TopPosition { get; set; }   // Vertical position for the category row
}
