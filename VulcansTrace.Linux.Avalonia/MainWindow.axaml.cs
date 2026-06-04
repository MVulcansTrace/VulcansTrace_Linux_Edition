using System;
using System.Collections.Specialized;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Media;
using Avalonia.Collections;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Interaction logic for MainWindow.axaml
/// </summary>
public partial class MainWindow : Window
{
    private TimelineViewModel? _timelineViewModel;

    public MainWindow()
    {
        InitializeComponent();

        var services = AgentFactory.Create(MachineRole.Workstation);
        var dialogService = new AvaloniaDialogService(this);
        var viewModel = new MainViewModel(services.Analyzer, services.EvidenceBuilder, dialogService, services.ProfileProvider, services.Agent, services.SuppressionStore, services.AuditHistoryStore, services.RemediationPlanBuilder, new TraceMapCorrelator(), services.LiveStreamAnalyzer, services.ScheduleStore, services.NotificationService, services.SessionStore, services.ThreatIntelStore);
        viewModel.RuleCatalog.LoadCatalog(services.RuleCatalog);
        viewModel.Agent.ShowAuditDiffAction = diff =>
        {
            var window = new Views.AuditDiffWindow();
            window.ViewModel.LoadDiff(diff);
            window.ShowDialog(this);
        };
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;

        DataContextChanged += (_, _) => HookTimelineViewModel();
        TimelineCanvas.SizeChanged += (_, _) => RenderTimeline();
        Closed += OnClosed;
        HookTimelineViewModel();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedMachineRole) && DataContext is MainViewModel vm)
        {
            var newServices = AgentFactory.Create(vm.SelectedMachineRole);
            vm.Agent.SetAgent(newServices.Agent, newServices.SessionStore);
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        UnhookTimelineViewModel();

        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged -= OnViewModelPropertyChanged;
            vm.Dispose();
        }
    }

    private void UnhookTimelineViewModel()
    {
        if (_timelineViewModel != null)
        {
            _timelineViewModel.TimelineEntries.CollectionChanged -= OnTimelineCollectionChanged;
            _timelineViewModel.TimelineEdges.CollectionChanged -= OnTimelineCollectionChanged;
            _timelineViewModel.Categories.CollectionChanged -= OnTimelineCollectionChanged;
            _timelineViewModel.PropertyChanged -= OnTimelinePropertyChanged;
            _timelineViewModel = null;
        }
    }

    private void HookTimelineViewModel()
    {
        UnhookTimelineViewModel();

        _timelineViewModel = (DataContext as MainViewModel)?.Timeline;

        if (_timelineViewModel != null)
        {
            _timelineViewModel.TimelineEntries.CollectionChanged += OnTimelineCollectionChanged;
            _timelineViewModel.TimelineEdges.CollectionChanged += OnTimelineCollectionChanged;
            _timelineViewModel.Categories.CollectionChanged += OnTimelineCollectionChanged;
            _timelineViewModel.PropertyChanged += OnTimelinePropertyChanged;
        }

        RenderTimeline();
    }

    private void OnTimelineCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void OnTimelinePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void RenderTimeline()
    {
        if (TimelineCanvas == null)
        {
            return;
        }

        TimelineCanvas.Children.Clear();

        if (_timelineViewModel == null || _timelineViewModel.TimelineEntries.Count == 0)
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

        var hasSelection = _timelineViewModel.SelectedFindingId != Guid.Empty;
        var connectedIds = _timelineViewModel.ConnectedFindingIds;

        // Draw correlation edges first so finding bars remain readable and easy to click.
        if (_timelineViewModel.IsTraceMapEnabled && !_timelineViewModel.IsEdgeRenderingSuppressed)
        {
            foreach (var edge in _timelineViewModel.TimelineEdges)
            {
                var fromX = leftPadding + (edge.FromEndPosition * usableWidth);
                var fromY = edge.FromTopPosition + (_timelineViewModel.RowHeight / 2.0);
                var toX = leftPadding + (edge.ToStartPosition * usableWidth);
                var toY = edge.ToTopPosition + (_timelineViewModel.RowHeight / 2.0);

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

        foreach (var entry in _timelineViewModel.TimelineEntries)
        {
            var start = leftPadding + (entry.StartPosition * usableWidth);
            var end = leftPadding + (entry.EndPosition * usableWidth);
            var barWidth = Math.Max(2, end - start);

            var bar = new Border
            {
                Width = barWidth,
                Height = _timelineViewModel.RowHeight,
                Background = GetSeverityBrush(entry.Severity),
                CornerRadius = new CornerRadius(3)
            };

            // Highlight / dim based on selection
            if (hasSelection && _timelineViewModel.IsTraceMapEnabled)
            {
                bar.Opacity = connectedIds.Contains(entry.FindingId) ? 1.0 : 0.25;
            }

            var tip = $"{entry.Category} | {entry.Severity}\n{entry.Description}\n{entry.StartTime:O} – {entry.EndTime:O}";
            ToolTip.SetTip(bar, tip);

            // Capture finding ID for click handler
            var findingId = entry.FindingId;
            bar.PointerPressed += (_, _) =>
            {
                if (_timelineViewModel != null)
                {
                    _timelineViewModel.SelectedFindingId = findingId;
                }
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
