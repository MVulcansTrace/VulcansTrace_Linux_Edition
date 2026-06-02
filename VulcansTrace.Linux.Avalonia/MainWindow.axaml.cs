using System;
using System.Collections.Specialized;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Media;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Core;
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
        var viewModel = new MainViewModel(services.Analyzer, services.EvidenceBuilder, dialogService, services.ProfileProvider, services.Agent, services.SuppressionStore, services.AuditHistoryStore, services.RemediationPlanBuilder, services.ScheduleStore, services.NotificationService, services.SessionStore);
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

            var tip = $"{entry.Category} | {entry.Severity}\n{entry.Description}\n{entry.StartTime:O} – {entry.EndTime:O}";
            ToolTip.SetTip(bar, tip);

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
}
