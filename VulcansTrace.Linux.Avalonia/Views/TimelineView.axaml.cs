using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Collections;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class TimelineView : UserControl
{
    // Vertical space reserved for the horizontal time axis at the top of the canvas.
    private const double MarkerHeight = 16;
    private const double LeftPadding = 8;
    private const double RightPadding = 8;

    private TimelineViewModel? _currentVm;

    public TimelineView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => HookViewModel();
        TimelineCanvas.SizeChanged += (_, _) => RenderTimeline();

        if (CloseDetailButton != null)
        {
            CloseDetailButton.Click += (_, _) =>
            {
                if (DataContext is TimelineViewModel vm) vm.SelectedFindingId = Guid.Empty;
            };
        }

        HookViewModel();
    }

    private void HookViewModel()
    {
        // Unsubscribe the previous view model so a DataContext swap doesn't leave
        // ghost handlers keeping the stale VM alive and driving this view.
        if (_currentVm != null)
        {
            _currentVm.TimelineEntries.CollectionChanged -= OnCollectionChanged;
            _currentVm.TimelineEdges.CollectionChanged -= OnCollectionChanged;
            _currentVm.Categories.CollectionChanged -= OnCollectionChanged;
            _currentVm.PropertyChanged -= OnPropertyChanged;
            _currentVm = null;
        }

        if (DataContext is TimelineViewModel vm)
        {
            _currentVm = vm;
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
        if (e.PropertyName is nameof(TimelineViewModel.TimelineEntries)
            or nameof(TimelineViewModel.TimelineEdges)
            or nameof(TimelineViewModel.Categories)
            or nameof(TimelineViewModel.CanvasHeight)
            or nameof(TimelineViewModel.IsTraceMapEnabled)
            or nameof(TimelineViewModel.SelectedFindingId))
        {
            RenderTimeline();
        }
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

        var usableWidth = Math.Max(1, width - LeftPadding - RightPadding);
        var hasSelection = vm.SelectedFindingId != Guid.Empty;
        var connectedIds = vm.ConnectedFindingIds;

        DrawSwimlaneGrid(vm, width);
        DrawTimeAxis(vm, width, usableWidth);

        // Draw correlation edges first so markers remain readable and easy to click.
        if (vm.IsTraceMapEnabled && !vm.IsEdgeRenderingSuppressed)
        {
            DrawEdges(vm, usableWidth, hasSelection, connectedIds);
        }

        DrawMarkers(vm, usableWidth, hasSelection, connectedIds);
    }

    private void DrawSwimlaneGrid(TimelineViewModel vm, double width)
    {
        var gridBrush = new SolidColorBrush(Color.Parse("#1E293B"), 0.5);
        var rowCount = vm.Categories.Count;

        for (var i = 0; i < rowCount; i++)
        {
            var y = vm.AxisHeight + vm.TopPadding + i * (vm.RowHeight + vm.RowGap) + vm.RowHeight;
            var line = new Line
            {
                StartPoint = new Point(0, y),
                EndPoint = new Point(width, y),
                Stroke = gridBrush,
                StrokeThickness = 1
            };
            TimelineCanvas.Children.Add(line);
        }
    }

    private void DrawTimeAxis(TimelineViewModel vm, double width, double usableWidth)
    {
        if (vm.MinTime == null || vm.MaxTime == null)
        {
            return;
        }

        var axisBrush = new SolidColorBrush(Color.Parse("#64748B"));
        var tickBrush = new SolidColorBrush(Color.Parse("#334155"));
        var textBrush = new SolidColorBrush(Color.Parse("#94A3B8"));

        // Horizontal baseline
        TimelineCanvas.Children.Add(new Line
        {
            StartPoint = new Point(0, vm.AxisHeight - 1),
            EndPoint = new Point(width, vm.AxisHeight - 1),
            Stroke = tickBrush,
            StrokeThickness = 1
        });

        var min = vm.MinTime.Value;
        var max = vm.MaxTime.Value;
        var total = max - min;
        if (total.TotalSeconds <= 0)
        {
            total = TimeSpan.FromSeconds(1);
        }

        var tickCount = ComputeTickCount(usableWidth);
        var labels = ComputeTickLabels(min, max, tickCount);

        for (var i = 0; i < labels.Count; i++)
        {
            var t = labels[i].time;
            var position = LeftPadding + ((t - min).TotalSeconds / total.TotalSeconds) * usableWidth;
            position = Math.Max(LeftPadding, Math.Min(width - RightPadding, position));

            // Tick line spanning the canvas
            TimelineCanvas.Children.Add(new Line
            {
                StartPoint = new Point(position, vm.AxisHeight),
                EndPoint = new Point(position, vm.CanvasHeight),
                Stroke = tickBrush,
                StrokeThickness = 1,
                Opacity = 0.4
            });

            // Tick mark on the axis
            TimelineCanvas.Children.Add(new Line
            {
                StartPoint = new Point(position, vm.AxisHeight - 6),
                EndPoint = new Point(position, vm.AxisHeight - 1),
                Stroke = axisBrush,
                StrokeThickness = 1
            });

            // Label
            var text = new TextBlock
            {
                Text = labels[i].label,
                FontSize = 12,
                FontFamily = new FontFamily("JetBrains Mono, Cascadia Code, Consolas, monospace"),
                Foreground = textBrush,
                TextAlignment = TextAlignment.Center,
                MaxWidth = 80,
                TextTrimming = TextTrimming.CharacterEllipsis,
                ClipToBounds = true
            };
            var labelX = Math.Max(4, Math.Min(width - 84, position - 40));
            Canvas.SetLeft(text, labelX);
            Canvas.SetTop(text, 4);
            TimelineCanvas.Children.Add(text);
        }
    }

    private static int ComputeTickCount(double usableWidth)
    {
        const double minTickSpacing = 90;
        var count = (int)Math.Floor(usableWidth / minTickSpacing);
        return Math.Clamp(count, 2, 8);
    }

    private static List<(DateTime time, string label)> ComputeTickLabels(DateTime min, DateTime max, int tickCount)
    {
        var total = max - min;
        if (total.TotalSeconds <= 0)
        {
            total = TimeSpan.FromSeconds(1);
        }

        var labels = new List<(DateTime, string)>();
        var format = total.TotalDays >= 1 ? "yyyy-MM-dd HH:mm" : "HH:mm:ss";

        for (var i = 0; i < tickCount; i++)
        {
            var fraction = i / (double)(tickCount - 1);
            var time = min.AddTicks((long)(total.Ticks * fraction));
            labels.Add((time, time.ToUniversalTime().ToString(format, CultureInfo.InvariantCulture)));
        }

        return labels;
    }

    private void DrawEdges(TimelineViewModel vm, double usableWidth, bool hasSelection, HashSet<Guid> connectedIds)
    {
        foreach (var edge in vm.TimelineEdges)
        {
            var fromX = LeftPadding + (edge.FromEndPosition * usableWidth);
            var fromY = vm.AxisHeight + edge.FromTopPosition + (vm.RowHeight / 2.0);
            var toX = LeftPadding + (edge.ToStartPosition * usableWidth);
            var toY = vm.AxisHeight + edge.ToTopPosition + (vm.RowHeight / 2.0);

            var line = new Line
            {
                StartPoint = new Point(fromX, fromY),
                EndPoint = new Point(toX, toY),
                Stroke = GetEdgeBrush(edge.CorrelationType),
                StrokeThickness = 1.5,
                StrokeDashArray = new AvaloniaList<double> { 4, 2 }
            };

            if (hasSelection)
            {
                var isConnected = connectedIds.Contains(edge.FromFindingId) && connectedIds.Contains(edge.ToFindingId);
                line.Opacity = isConnected ? 1.0 : 0.15;
            }

            ToolTip.SetTip(line, edge.Narrative);
            TimelineCanvas.Children.Add(line);
        }
    }

    private void DrawMarkers(TimelineViewModel vm, double usableWidth, bool hasSelection, HashSet<Guid> connectedIds)
    {
        foreach (var entry in vm.TimelineEntries)
        {
            var start = LeftPadding + (entry.StartPosition * usableWidth);
            var end = LeftPadding + (entry.EndPosition * usableWidth);
            var durationWidth = Math.Max(2, end - start);
            var markerWidth = Math.Max(durationWidth, 10);

            var centerY = vm.AxisHeight + entry.TopPosition + (vm.RowHeight / 2.0);
            var top = centerY - (MarkerHeight / 2.0);

            var baseBrush = GetSeverityBrush(entry.Severity);
            var strokeBrush = GetSeverityStrokeBrush(entry.Severity);

            // Selection glow behind the marker
            if (hasSelection && entry.FindingId == vm.SelectedFindingId)
            {
                var glow = new Ellipse
                {
                    Width = 28,
                    Height = 28,
                    Fill = new SolidColorBrush(Color.Parse("#3B82F6"), 0.25),
                    IsHitTestVisible = false
                };
                Canvas.SetLeft(glow, start + (markerWidth / 2.0) - 14);
                Canvas.SetTop(glow, centerY - 14);
                TimelineCanvas.Children.Add(glow);
            }

            var marker = new Border
            {
                Width = markerWidth,
                Height = MarkerHeight,
                Background = baseBrush,
                BorderBrush = strokeBrush,
                BorderThickness = new Thickness(1.5),
                CornerRadius = new CornerRadius(6)
            };

            if (hasSelection && vm.IsTraceMapEnabled)
            {
                marker.Opacity = connectedIds.Contains(entry.FindingId) ? 1.0 : 0.25;
            }

            var tip = $"{entry.Category} | {entry.Severity}\n{entry.Description}\n{entry.StartTime:O} – {entry.EndTime:O}";
            ToolTip.SetTip(marker, tip);

            var findingId = entry.FindingId;
            marker.PointerPressed += (_, _) =>
            {
                vm.SelectedFindingId = findingId;
            };
            marker.Cursor = new Cursor(StandardCursorType.Hand);

            Canvas.SetLeft(marker, start);
            Canvas.SetTop(marker, top);

            TimelineCanvas.Children.Add(marker);

            // Accent ring for the selected marker
            if (hasSelection && entry.FindingId == vm.SelectedFindingId)
            {
                var ring = new Border
                {
                    Width = markerWidth + 6,
                    Height = MarkerHeight + 6,
                    BorderBrush = new SolidColorBrush(Color.Parse("#3B82F6")),
                    BorderThickness = new Thickness(2),
                    CornerRadius = new CornerRadius(8),
                    Background = Brushes.Transparent,
                    IsHitTestVisible = false
                };
                Canvas.SetLeft(ring, start - 3);
                Canvas.SetTop(ring, top - 3);
                TimelineCanvas.Children.Add(ring);
            }
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

    private static IBrush GetSeverityStrokeBrush(Severity severity)
    {
        return severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.Parse("#f87171")),
            Severity.High => new SolidColorBrush(Color.Parse("#fb923c")),
            Severity.Medium => new SolidColorBrush(Color.Parse("#facc15")),
            Severity.Low => new SolidColorBrush(Color.Parse("#4ade80")),
            _ => new SolidColorBrush(Color.Parse("#94a3b8"))
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
