using System;
using System.ComponentModel;
using Avalonia.Controls;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Interaction logic for MainWindow.axaml
/// </summary>
public partial class MainWindow : Window
{
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
        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged -= OnViewModelPropertyChanged;
            vm.Dispose();
        }
    }
}
