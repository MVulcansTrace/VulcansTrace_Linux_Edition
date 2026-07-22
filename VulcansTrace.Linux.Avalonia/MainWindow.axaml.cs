using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
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
    private CancellationTokenSource? _transitionCts;
    private AgentServices? _rootServices;
    private AgentServices? _activeRoleServices;

    public MainWindow()
    {
        InitializeComponent();

        var services = AgentFactory.Create(MachineRole.Workstation);
        _rootServices = services;
        var dialogService = new AvaloniaDialogService(this);
        var viewModel = new MainViewModel(services.Analyzer, services.EvidenceBuilder, dialogService, services.ProfileProvider, services.Agent, services.SuppressionStore, services.PinnedFindingStore, services.PinnedMessageStore, services.AuditHistoryStore, services.RemediationPlanBuilder, services.RemediationExecutor, services.TraceMapCorrelator, services.LiveStreamAnalyzer, services.PolicyStore, services.ScheduleStore, services.NotificationService, services.SessionStore, services.ThreatIntelStore, services.DoctorService, services.MemoryStore, services.NotificationSettingsStore, services.AnalystActionStore, services.AnalystActionLogger);
        viewModel.RuleCatalog.LoadCatalog(services.RuleCatalog);
        viewModel.Agent.ShowAuditDiffAction = diff =>
        {
            var window = new Views.AuditDiffWindow();
            window.ViewModel.LoadDiff(diff);
            window.ShowDialog(this);
        };
        viewModel.Agent.ShowLogDiffDemoAction = () => viewModel.ShowLogDiffDemoAsync();
        viewModel.ShowAdvancedScanOptionsAction = () =>
        {
            var window = new Views.AdvancedScanOptionsWindow { DataContext = viewModel };
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
            var previousRoleServices = _activeRoleServices;
            var newServices = AgentFactory.Create(vm.SelectedMachineRole);
            try
            {
                vm.Agent.SetAgent(newServices.Agent, newServices.SessionStore);

                // AgentFactory rebuilds the policy store for the new agent's provider. The catalog
                // editor must write to that same store instance or saved overrides would be invisible
                // to the active agent for the rest of the session. Track the new role and store here.
                vm.RuleCatalog.CurrentMachineRole = vm.SelectedMachineRole;
                vm.RuleCatalog.UpdatePolicyStore(newServices.PolicyStore);

                _activeRoleServices = newServices;
                previousRoleServices?.Dispose();
            }
            catch
            {
                newServices.Dispose();
                throw;
            }
        }

        if (e.PropertyName == nameof(MainViewModel.SelectedContent))
        {
            _ = AnimateContentTransitionAsync();
        }
    }

    private async Task AnimateContentTransitionAsync()
    {
        if (_mainContent == null) return;

        // Machine mode: instant content switch so harnesses never observe a
        // mid-fade tree (and never wait on animation timing).
        if (Services.MachineMode.IsEnabled) return;

        // Cancel any in-flight transition so rapid navigation doesn't stack animations.
        var previousTransition = _transitionCts;
        var transitionCts = new CancellationTokenSource();
        _transitionCts = transitionCts;
        previousTransition?.Cancel();
        var token = transitionCts.Token;

        try
        {
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
            await fadeOut.RunAsync(_mainContent, token);

            if (token.IsCancellationRequested)
                return;

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
            await fadeIn.RunAsync(_mainContent, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // Expected when users navigate quickly or the window closes mid-transition.
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Content transition failed: {ex}");
        }
        finally
        {
            if (ReferenceEquals(_transitionCts, transitionCts))
                _transitionCts = null;

            transitionCts.Dispose();
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        var activeRoleServices = _activeRoleServices;
        var rootServices = _rootServices;
        _activeRoleServices = null;
        _rootServices = null;

        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged -= OnViewModelPropertyChanged;
            vm.Dispose();
        }

        _transitionCts?.Cancel();
        _transitionCts = null;
        activeRoleServices?.Dispose();
        rootServices?.Dispose();
    }
}
