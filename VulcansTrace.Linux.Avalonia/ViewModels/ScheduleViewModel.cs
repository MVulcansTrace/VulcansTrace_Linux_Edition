using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Autonomous;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.Views;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for managing recurring audit schedules.
/// </summary>
public sealed class ScheduleViewModel : ViewModelBase
{
    private readonly IScheduleStore _store;
    private readonly IAuditHistoryStore _historyStore;
    private readonly INotificationSettingsStore _notificationSettingsStore;
    private readonly INotificationService _fallbackNotificationService;
    private readonly IDialogService _dialogService;
    private readonly AnalystActionLogger? _analystActionLogger;
    private ScheduleRowViewModel? _selectedRow;
    private string _statusMessage = "";

    /// <summary>
    /// Gets the collection of configured schedules.
    /// </summary>
    public ObservableCollection<ScheduleRowViewModel> Rows { get; } = new();

    /// <summary>
    /// Gets or sets the currently selected schedule row.
    /// </summary>
    public ScheduleRowViewModel? SelectedRow
    {
        get => _selectedRow;
        set
        {
            if (SetField(ref _selectedRow, value))
            {
                DeleteCommand.RaiseCanExecuteChanged();
                EditCommand.RaiseCanExecuteChanged();
                EnableCommand.RaiseCanExecuteChanged();
                DisableCommand.RaiseCanExecuteChanged();
                RunNowCommand.RaiseCanExecuteChanged();
                InstallCronCommand.RaiseCanExecuteChanged();
                UninstallCronCommand.RaiseCanExecuteChanged();
                OpenOutputCommand.RaiseCanExecuteChanged();
                RemediateCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>
    /// Gets the status message text.
    /// </summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets the command to add a new schedule.</summary>
    public AsyncRelayCommand AddCommand { get; }

    /// <summary>Gets the command to edit the selected schedule.</summary>
    public AsyncRelayCommand EditCommand { get; }

    /// <summary>Gets the command to delete the selected schedule.</summary>
    public AsyncRelayCommand DeleteCommand { get; }

    /// <summary>Gets the command to enable the selected schedule.</summary>
    public AsyncRelayCommand EnableCommand { get; }

    /// <summary>Gets the command to disable the selected schedule.</summary>
    public AsyncRelayCommand DisableCommand { get; }

    /// <summary>Gets the command to run the selected schedule now.</summary>
    public AsyncRelayCommand RunNowCommand { get; }

    /// <summary>Gets the command to install the selected schedule into the system crontab.</summary>
    public AsyncRelayCommand InstallCronCommand { get; }

    /// <summary>Gets the command to uninstall the selected schedule from the system crontab.</summary>
    public AsyncRelayCommand UninstallCronCommand { get; }

    /// <summary>Gets the command to open the selected schedule's output directory.</summary>
    public AsyncRelayCommand OpenOutputCommand { get; }

    /// <summary>Gets the command to review and execute remediation for the selected schedule.</summary>
    public AsyncRelayCommand RemediateCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ScheduleViewModel"/> class.
    /// </summary>
    public ScheduleViewModel(IScheduleStore store, IAuditHistoryStore historyStore, INotificationSettingsStore notificationSettingsStore, INotificationService fallbackNotificationService, IDialogService dialogService, AnalystActionLogger? analystActionLogger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _historyStore = historyStore ?? throw new ArgumentNullException(nameof(historyStore));
        _notificationSettingsStore = notificationSettingsStore ?? throw new ArgumentNullException(nameof(notificationSettingsStore));
        _fallbackNotificationService = fallbackNotificationService ?? throw new ArgumentNullException(nameof(fallbackNotificationService));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        _analystActionLogger = analystActionLogger;

        AddCommand = new AsyncRelayCommand(
            async _ => await AddAsync(),
            _ => true,
            ex => StatusMessage = $"Add failed: {ex.Message}");

        EditCommand = new AsyncRelayCommand(
            async _ => await EditAsync(),
            _ => SelectedRow != null,
            ex => StatusMessage = $"Edit failed: {ex.Message}");

        DeleteCommand = new AsyncRelayCommand(
            async _ => await DeleteAsync(),
            _ => SelectedRow != null,
            ex => StatusMessage = $"Delete failed: {ex.Message}");

        EnableCommand = new AsyncRelayCommand(
            async _ => await ToggleAsync(enabled: true),
            _ => SelectedRow != null && !SelectedRow.Schedule.Enabled,
            ex => StatusMessage = $"Enable failed: {ex.Message}");

        DisableCommand = new AsyncRelayCommand(
            async _ => await ToggleAsync(enabled: false),
            _ => SelectedRow != null && SelectedRow.Schedule.Enabled,
            ex => StatusMessage = $"Disable failed: {ex.Message}");

        RunNowCommand = new AsyncRelayCommand(
            async _ => await RunNowAsync(),
            _ => SelectedRow != null && SelectedRow.Schedule.Enabled,
            ex => StatusMessage = $"Run failed: {ex.Message}");

        InstallCronCommand = new AsyncRelayCommand(
            async _ => await InstallCronAsync(),
            _ => SelectedRow != null,
            ex => StatusMessage = $"Install cron failed: {ex.Message}");

        UninstallCronCommand = new AsyncRelayCommand(
            async _ => await UninstallCronAsync(),
            _ => SelectedRow != null,
            ex => StatusMessage = $"Uninstall cron failed: {ex.Message}");

        OpenOutputCommand = new AsyncRelayCommand(
            async _ => await OpenOutputAsync(),
            _ => SelectedRow != null && !string.IsNullOrWhiteSpace(SelectedRow.Schedule.OutputDirectory),
            ex => StatusMessage = $"Open output failed: {ex.Message}");

        RemediateCommand = new AsyncRelayCommand(
            async _ => await RemediateAsync(),
            _ => SelectedRow != null && SelectedRow.Schedule.Enabled && SelectedRow.Schedule.AllowAutoRemediate,
            ex => StatusMessage = $"Remediate failed: {ex.Message}");

        Refresh();
    }

    /// <summary>
    /// Reloads schedules from the store and refreshes cron status.
    /// </summary>
    public void Refresh()
    {
        var installedIds = CrontabManager.GetInstalledScheduleIds().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var selectedId = SelectedRow?.Schedule.Id;

        Rows.Clear();
        foreach (var schedule in _store.GetAll())
        {
            var row = new ScheduleRowViewModel(schedule)
            {
                IsInstalledInCron = installedIds.Contains(schedule.Id)
            };
            Rows.Add(row);
        }

        if (selectedId != null)
        {
            SelectedRow = Rows.FirstOrDefault(r => r.Schedule.Id.Equals(selectedId, StringComparison.OrdinalIgnoreCase));
        }
    }

    private async Task AddAsync()
    {
        var window = new ScheduleEditWindow();
        window.Title = "Add Schedule";

        var owner = GetOwnerWindow();
        if (owner == null)
            return;

        var result = await window.ShowDialog<bool?>(owner);
        if (result != true)
            return;

        var schedule = window.ViewModel.ToSchedule();
        if (_store.GetAll().Any(s => s.Name.Equals(schedule.Name, StringComparison.OrdinalIgnoreCase)))
        {
            StatusMessage = $"A schedule named '{schedule.Name}' already exists.";
            return;
        }
        _store.Save(schedule);
        Refresh();
        StatusMessage = $"Schedule '{schedule.Name}' created.";
        await (_analystActionLogger?.LogScheduleAddedAsync("avalonia", schedule.Id) ?? Task.CompletedTask);
    }

    private async Task EditAsync()
    {
        if (SelectedRow == null)
            return;

        var window = new ScheduleEditWindow();
        window.Title = "Edit Schedule";
        window.ViewModel.LoadSchedule(SelectedRow.Schedule);

        var owner = GetOwnerWindow();
        if (owner == null)
            return;

        var result = await window.ShowDialog<bool?>(owner);
        if (result != true)
            return;

        var updated = window.ViewModel.ToSchedule(SelectedRow.Schedule.Id);
        if (_store.GetAll().Any(s => s.Name.Equals(updated.Name, StringComparison.OrdinalIgnoreCase) && !s.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase)))
        {
            StatusMessage = $"A schedule named '{updated.Name}' already exists.";
            return;
        }
        _store.Save(updated);
        Refresh();
        StatusMessage = $"Schedule '{updated.Name}' updated.";
        await (_analystActionLogger?.LogScheduleEditedAsync("avalonia", updated.Id) ?? Task.CompletedTask);
    }

    private async Task DeleteAsync()
    {
        if (SelectedRow == null)
            return;

        var schedule = SelectedRow.Schedule;
        _store.Delete(schedule.Id);
        Refresh();
        StatusMessage = $"Schedule '{schedule.Name}' deleted.";
        await (_analystActionLogger?.LogScheduleDeletedAsync("avalonia", schedule.Id) ?? Task.CompletedTask);
    }

    private async Task ToggleAsync(bool enabled)
    {
        if (SelectedRow == null)
            return;

        var schedule = SelectedRow.Schedule;
        _store.Save(schedule with { Enabled = enabled });
        Refresh();
        StatusMessage = $"Schedule '{schedule.Name}' {(enabled ? "enabled" : "disabled")}.";
        if (enabled)
            await (_analystActionLogger?.LogScheduleEnabledAsync("avalonia", schedule.Id) ?? Task.CompletedTask);
        else
            await (_analystActionLogger?.LogScheduleDisabledAsync("avalonia", schedule.Id) ?? Task.CompletedTask);
    }

    private async Task RunNowAsync()
    {
        if (SelectedRow == null)
            return;

        var schedule = SelectedRow.Schedule;
        StatusMessage = $"Running '{schedule.Name}'...";

        await Task.Run(async () =>
        {
            using var cts = new CancellationTokenSource();
            using var services = AgentFactory.Create(schedule.MachineRole);
            var result = await services.Agent.RunAuditAsync(schedule.Intent, rawLog: null, cts.Token);
            var criticalCount = result.AgentFindings.Count(f => f.Severity == Severity.Critical);

            _store.Save(schedule with { LastRunUtc = DateTime.UtcNow });

            // Persist audit result to history store (consistent with CLI schedule run)
            var snapshotFindings = result.AgentFindings.Select(f => new AuditSnapshotFinding
            {
                RuleId = f.RuleId ?? "",
                Target = f.Target,
                Severity = f.Severity.ToString(),
                Confidence = f.Confidence.ToString(),
                EvidenceSignals = f.EvidenceSignals,
                ShortDescription = f.ShortDescription,
                Category = f.Category,
                GroupedCount = f.GroupedCount,
                RepresentativeTargets = f.RepresentativeTargets,
                RiskDrivers = f.RiskDrivers,
                Fingerprint = f.Fingerprint
            }).ToList();

            _historyStore.Append(new AuditHistoryEntry
            {
                SnapshotId = Guid.NewGuid().ToString("N")[..8],
                TimestampUtc = result.UtcTimestamp,
                Intent = result.Intent,
                TotalFindings = result.AgentFindings.Count,
                CriticalCount = result.AgentFindings.Count(f => f.Severity == Severity.Critical),
                HighCount = result.AgentFindings.Count(f => f.Severity == Severity.High),
                MediumCount = result.AgentFindings.Count(f => f.Severity == Severity.Medium),
                LowCount = result.AgentFindings.Count(f => f.Severity == Severity.Low),
                InfoCount = result.AgentFindings.Count(f => f.Severity == Severity.Info),
                WarningCount = result.Warnings.Count,
                Exported = false,
                PassedCount = result.PassedCount,
                FailedCount = result.FailedCount,
                SuppressedCount = result.SuppressedCount,
                CrashedCount = result.CrashedCount,
                SnapshotFindings = snapshotFindings
            });

            Dispatcher.UIThread.Post(Refresh);

            if (schedule.NotifyOnCritical && criticalCount > 0)
            {
                var notifier = CreateNotificationService(schedule.NotificationChannel);
                try
                {
                    await notifier.NotifyCriticalFindingsAsync(schedule.Name, criticalCount, cts.Token);
                }
                finally
                {
                    (notifier as IDisposable)?.Dispose();
                }
            }

            if (schedule.AutonomousDriftResponse)
            {
                // Best-effort: drift response reuses the already-completed audit (`result`) so no
                // redundant second audit runs, and must never fail the run or alter its outcome.
                var driftNotifier = CreateNotificationService(schedule.NotificationChannel);
                try
                {
                    var responder = new AutonomousDriftResponder(
                        services.Agent,
                        services.BaselineStore,
                        driftNotifier,
                        ResolveAlertSigningKey,
                        services.RemediationPlanBuilder);
                    await responder.RespondToDriftAsync(schedule, msg => Dispatcher.UIThread.Post(() => StatusMessage = msg), result, cts.Token);
                }
                catch (Exception ex)
                {
                    Dispatcher.UIThread.Post(() => StatusMessage = $"Drift response failed: {ex.Message}");
                }
                finally
                {
                    (driftNotifier as IDisposable)?.Dispose();
                }
            }

            Dispatcher.UIThread.Post(() =>
            {
                StatusMessage = $"'{schedule.Name}' completed. {criticalCount} critical finding(s).";
            });
        });
    }

    private async Task RemediateAsync()
    {
        if (SelectedRow == null)
            return;

        var schedule = SelectedRow.Schedule;
        if (!schedule.Enabled)
        {
            StatusMessage = $"Schedule '{schedule.Name}' is disabled.";
            return;
        }

        if (!schedule.AllowAutoRemediate)
        {
            StatusMessage = $"Remediation is not enabled for schedule '{schedule.Name}'.";
            return;
        }

        var owner = GetOwnerWindow();
        if (owner == null)
        {
            StatusMessage = "Remediation preview unavailable: no parent window.";
            return;
        }

        StatusMessage = $"Building remediation preview for '{schedule.Name}'...";

        using var services = AgentFactory.Create(schedule.MachineRole);
        var policy = BuildScheduleRemediationPolicy(schedule);

        // Build the remediation plan off the UI thread, applying the schedule's rule-prefix scope.
        RemediationPlan plan;
        try
        {
            plan = await Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource();
                var result = await services.Agent.RunAuditAsync(schedule.Intent, rawLog: null, cts.Token);
                var scopedFindings = RemediationScopeFilter.Apply(result.AgentFindings, schedule.AllowedRemediationRulePrefixes);
                return services.RemediationPlanBuilder.Build(scopedFindings);
            });
        }
        catch (OperationCanceledException)
        {
            StatusMessage = $"Remediation preview for '{schedule.Name}' was cancelled.";
            return;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Preview failed: audit for '{schedule.Name}' could not complete: {ex.Message}";
            return;
        }

        var previewViewModel = new RemediationPreviewViewModel(
            plan,
            policy,
            () => Task.Run(() => ExecuteScheduleRemediationAsync(services, plan, policy)));

        Dispatcher.UIThread.Post(() => StatusMessage = $"Remediation preview ready for '{schedule.Name}'.");

        var window = new RemediationPreviewWindow(previewViewModel);
        // We are on the UI thread here (RemediateAsync resumed after the plan-building Task.Run).
        // The dialog stays open across execution so the operator can review the result; it returns
        // here only when they click Close.
        await window.ShowDialog(owner);

        var executionResult = previewViewModel.ExecutionResult;
        StatusMessage = executionResult == null
            ? $"Remediation cancelled for '{schedule.Name}'."
            : executionResult.AllSucceeded && executionResult.TotalCommandsExecuted > 0
                ? $"Remediation completed for '{schedule.Name}'."
                : executionResult.AllSucceeded
                    ? $"No remediation commands executed for '{schedule.Name}'."
                    : $"Remediation completed with failures for '{schedule.Name}'.";
    }

    private async Task<RemediationExecutionResult> ExecuteScheduleRemediationAsync(
        AgentServices services,
        RemediationPlan plan,
        AutoFixPolicy policy)
    {
        using var cts = new CancellationTokenSource();
        var executionResult = await services.RemediationExecutor.ExecuteAsync(plan, policy, dryRun: false, cts.Token);

        // Record remediation attempts via memory store (best-effort).
        try
        {
            var snapshot = services.MemoryStore.Load();
            if (snapshot != null && snapshot.RuleHistory.Count > 0)
            {
                var attemptedRuleIds = executionResult.Sections
                    .Where(s => s.ApplyResults.Any(r => !r.Skipped))
                    .Select(s => s.RuleId)
                    .Where(r => !string.IsNullOrWhiteSpace(r) && snapshot.RuleHistory.ContainsKey(r))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (attemptedRuleIds.Count > 0)
                {
                    var timestamp = executionResult.CompletedAtUtc == default
                        ? DateTime.UtcNow
                        : executionResult.CompletedAtUtc;
                    var updatedHistory = new RuleMemoryRecorder().MarkRemediationAttempt(
                        attemptedRuleIds,
                        timestamp,
                        snapshot.RuleHistory);

                    await services.MemoryStore.SaveAsync(snapshot with
                    {
                        UtcTimestamp = DateTime.UtcNow,
                        RuleHistory = updatedHistory
                    }).ConfigureAwait(false);
                }
            }
        }
        catch
        {
            // Best-effort memory update.
        }

        return executionResult;
    }

    private static AutoFixPolicy BuildScheduleRemediationPolicy(AuditSchedule schedule) => new()
    {
        AllowReadOnly = true,
        AllowConfigChange = true,
        AllowServiceRestart = schedule.AllowRemediationRestart,
        AllowPackageInstall = schedule.AllowRemediationPackages,
        AllowDestructive = false,
        AllowUnknown = false,
        RequireValidation = true,
        RequireRollbackGuidance = true
    };

    private async Task InstallCronAsync()
    {
        if (SelectedRow == null)
            return;

        await Task.Run(() => CrontabManager.Install(SelectedRow.Schedule));
        Refresh();
        StatusMessage = $"Cron entry installed for '{SelectedRow.Schedule.Name}'.";
    }

    private async Task UninstallCronAsync()
    {
        if (SelectedRow == null)
            return;

        await Task.Run(() => CrontabManager.Uninstall(SelectedRow.Schedule.Id));
        Refresh();
        StatusMessage = $"Cron entry uninstalled for '{SelectedRow.Schedule.Name}'.";
    }

    private Task OpenOutputAsync()
    {
        if (SelectedRow == null)
            return Task.CompletedTask;

        var dir = SelectedRow.Schedule.OutputDirectory;
        if (string.IsNullOrWhiteSpace(dir))
            return Task.CompletedTask;

        Directory.CreateDirectory(dir);

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "xdg-open",
                ArgumentList = { dir },
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
        catch
        {
            // Best-effort: silently degrade if xdg-open is unavailable
        }

        return Task.CompletedTask;
    }

    private static byte[]? ResolveAlertSigningKey(string scheduleId)
    {
        var keyHex = Environment.GetEnvironmentVariable("VT_ALERT_SIGNING_KEY");
        if (!string.IsNullOrWhiteSpace(keyHex))
        {
            try
            {
                return Convert.FromHexString(keyHex.Trim());
            }
            catch
            {
                // Fall back to deterministic key if env var is invalid.
            }
        }
        return null;
    }

    private INotificationService CreateNotificationService(NotificationChannel channel)
    {
        if (_notificationSettingsStore?.Settings is { Enabled: false })
            return new NullNotificationService();

        var settings = _notificationSettingsStore?.Settings ?? new NotificationSettings { Channel = channel };
        return channel switch
        {
            NotificationChannel.Email => new EmailNotificationService(settings with { Channel = NotificationChannel.Email }),
            NotificationChannel.Webhook => new WebhookNotificationService(settings with { Channel = NotificationChannel.Webhook }),
            _ => _fallbackNotificationService
        };
    }

    private static INotificationService CreateEmailService(NotificationSettings settings)
    {
        return new EmailNotificationService(settings);
    }

    private static INotificationService CreateWebhookService(NotificationSettings settings)
    {
        return new WebhookNotificationService(settings);
    }

    private static Window? GetOwnerWindow()
    {
        if (global::Avalonia.Application.Current?.ApplicationLifetime is global::Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
        {
            return desktop.MainWindow;
        }
        return null;
    }
}
