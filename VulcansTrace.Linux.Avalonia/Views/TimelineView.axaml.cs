using System;
using System.Collections.Specialized;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Media;
using Avalonia.Collections;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class TimelineView : UserControl
{
    public TimelineView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => HookViewModel();
        TimelineCanvas.SizeChanged += (_, _) => RenderTimeline();
        HookViewModel();
    }

    private void HookViewModel()
    {
        if (DataContext is TimelineViewModel vm)
        {
            vm.TimelineEntries.CollectionChanged += OnCollectionChanged;
            vm.TimelineEdges.CollectionChanged += OnCollectionChanged;
            vm.Categories.CollectionChanged += OnCollectionChanged;
            vm.PropertyChanged += OnPropertyChanged;
        }
        RenderTimeline();
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void OnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void RenderTimeline()
    {
        if (TimelineCanvas == null) return;

        TimelineCanvas.Children.Clear();

        if (DataContext is not TimelineViewModel vm || vm.TimelineEntries.Count == 0)
        {
            return;
        }

        var width = TimelineCanvas.Bounds.Width;
        if (width <= 0)
        {
            return;
        }

        const double leftPadding = 8;
        const double rightPadding = 8;
        var usableWidth = Math.Max(1, width - leftPadding - rightPadding);

        var hasSelection = vm.SelectedFindingId != Guid.Empty;
        var connectedIds = vm.ConnectedFindingIds;

        // Draw correlation edges first so finding bars remain readable and easy to click.
        if (vm.IsTraceMapEnabled && !vm.IsEdgeRenderingSuppressed)
        {
            foreach (var edge in vm.TimelineEdges)
            {
                var fromX = leftPadding + (edge.FromEndPosition * usableWidth);
                var fromY = edge.FromTopPosition + (vm.RowHeight / 2.0);
                var toX = leftPadding + (edge.ToStartPosition * usableWidth);
                var toY = edge.ToTopPosition + (vm.RowHeight / 2.0);

                var line = new Line
                {
                    StartPoint = new Point(fromX, fromY),
                    EndPoint = new Point(toX, toY),
                    Stroke = GetEdgeBrush(edge.CorrelationType),
                    StrokeThickness = 1.5,
                    StrokeDashArray = new AvaloniaList<double> { 4, 2 }
                };

                // Highlight / dim based on selection
                if (hasSelection)
                {
                    var isConnected = connectedIds.Contains(edge.FromFindingId) && connectedIds.Contains(edge.ToFindingId);
                    line.Opacity = isConnected ? 1.0 : 0.15;
                }

                ToolTip.SetTip(line, edge.Narrative);
                TimelineCanvas.Children.Add(line);
            }
        }

        foreach (var entry in vm.TimelineEntries)
        {
            var start = leftPadding + (entry.StartPosition * usableWidth);
            var end = leftPadding + (entry.EndPosition * usableWidth);
            var barWidth = Math.Max(2, end - start);

            var bar = new Border
            {
                Width = barWidth,
                Height = vm.RowHeight,
                Background = GetSeverityBrush(entry.Severity),
                CornerRadius = new CornerRadius(3)
            };

            // Highlight / dim based on selection
            if (hasSelection && vm.IsTraceMapEnabled)
            {
                bar.Opacity = connectedIds.Contains(entry.FindingId) ? 1.0 : 0.25;
            }

            var tip = $"{entry.Category} | {entry.Severity}\n{entry.Description}\n{entry.StartTime:O} – {entry.EndTime:O}";
            ToolTip.SetTip(bar, tip);

            // Capture finding ID for click handler
            var findingId = entry.FindingId;
            bar.PointerPressed += (_, _) =>
            {
                vm.SelectedFindingId = findingId;
            };

            Canvas.SetLeft(bar, start);
            Canvas.SetTop(bar, entry.TopPosition);

            TimelineCanvas.Children.Add(bar);
        }
    }

    private static IBrush GetSeverityBrush(Severity severity)
    {
        return severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.Parse("#ef4444")),
            Severity.High => new SolidColorBrush(Color.Parse("#f97316")),
            Severity.Medium => new SolidColorBrush(Color.Parse("#eab308")),
            Severity.Low => new SolidColorBrush(Color.Parse("#22c55e")),
            _ => new SolidColorBrush(Color.Parse("#64748b"))
        };
    }

    private static IBrush GetEdgeBrush(CorrelationType type)
    {
        return type switch
        {
            CorrelationType.EscalatesTo => new SolidColorBrush(Color.Parse("#38bdf8")), // cyan
            CorrelationType.SameHost => new SolidColorBrush(Color.Parse("#a78bfa")),    // purple
            CorrelationType.TemporalSequence => new SolidColorBrush(Color.Parse("#34d399")), // green
            _ => new SolidColorBrush(Color.Parse("#94a3b8"))
        };
    }
}
