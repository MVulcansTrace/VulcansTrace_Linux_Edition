using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Interaction logic for MainWindow.axaml
/// </summary>
public partial class MainWindow : Window
{
    private ContentControl? _mainContent;

    public MainWindow()
    {
        InitializeComponent();

        var services = AgentFactory.Create(MachineRole.Workstation);
        var dialogService = new AvaloniaDialogService(this);
        var viewModel = new MainViewModel(services.Analyzer, services.EvidenceBuilder, dialogService, services.ProfileProvider, services.Agent, services.SuppressionStore, services.AuditHistoryStore, services.RemediationPlanBuilder, services.RemediationExecutor, services.TraceMapCorrelator, services.LiveStreamAnalyzer, services.ScheduleStore, services.NotificationService, services.SessionStore, services.ThreatIntelStore, services.DoctorService);
        viewModel.RuleCatalog.LoadCatalog(services.RuleCatalog);
        viewModel.Agent.ShowAuditDiffAction = diff =>
        {
            var window = new Views.AuditDiffWindow();
            window.ViewModel.LoadDiff(diff);
            window.ShowDialog(this);
        };
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
        Closed += OnClosed;

        // Defer control lookup until after layout
        Dispatcher.UIThread.Post(() => _mainContent = this.FindControl<ContentControl>("MainContent"));
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.SelectedMachineRole) && DataContext is MainViewModel vm)
        {
            var newServices = AgentFactory.Create(vm.SelectedMachineRole);
            vm.Agent.SetAgent(newServices.Agent, newServices.SessionStore);
        }

        if (e.PropertyName == nameof(MainViewModel.SelectedContent))
        {
            _ = AnimateContentTransitionAsync();
        }
    }

    private async Task AnimateContentTransitionAsync()
    {
        if (_mainContent == null) return;

        // Ensure render transform is set up for translation
        _mainContent.RenderTransform = new TranslateTransform(0, 0);

        // Fade out + slide down
        var fadeOut = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(80),
            Easing = new CubicEaseOut(),
            Children =
            {
                new KeyFrame
                {
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 0.0),
                        new Setter(Visual.RenderTransformProperty, new TranslateTransform(0, 8))
                    },
                    KeyTime = TimeSpan.FromMilliseconds(80)
                }
            }
        };
        await fadeOut.RunAsync(_mainContent);

        // Fade in + slide up (content has already changed via binding during the fade out)
        var fadeIn = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(180),
            Easing = new CubicEaseOut(),
            Children =
            {
                new KeyFrame
                {
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 1.0),
                        new Setter(Visual.RenderTransformProperty, new TranslateTransform(0, 0))
                    },
                    KeyTime = TimeSpan.FromMilliseconds(180)
                }
            }
        };
        await fadeIn.RunAsync(_mainContent);
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged -= OnViewModelPropertyChanged;
            vm.Dispose();
        }
    }
}
