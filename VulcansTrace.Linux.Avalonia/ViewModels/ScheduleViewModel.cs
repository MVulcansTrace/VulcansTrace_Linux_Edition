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
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.Views;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for managing recurring audit schedules.
/// </summary>
public sealed class ScheduleViewModel : ViewModelBase
{
    private readonly IScheduleStore _store;
    private readonly IAuditHistoryStore _historyStore;
    private readonly INotificationService _fallbackNotificationService;
    private readonly IDialogService _dialogService;
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

    /// <summary>
    /// Initializes a new instance of the <see cref="ScheduleViewModel"/> class.
    /// </summary>
    public ScheduleViewModel(IScheduleStore store, IAuditHistoryStore historyStore, INotificationService fallbackNotificationService, IDialogService dialogService)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _historyStore = historyStore ?? throw new ArgumentNullException(nameof(historyStore));
        _fallbackNotificationService = fallbackNotificationService ?? throw new ArgumentNullException(nameof(fallbackNotificationService));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));

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
    }

    private Task DeleteAsync()
    {
        if (SelectedRow == null)
            return Task.CompletedTask;

        _store.Delete(SelectedRow.Schedule.Id);
        Refresh();
        StatusMessage = $"Schedule '{SelectedRow.Schedule.Name}' deleted.";
        return Task.CompletedTask;
    }

    private Task ToggleAsync(bool enabled)
    {
        if (SelectedRow == null)
            return Task.CompletedTask;

        _store.Save(SelectedRow.Schedule with { Enabled = enabled });
        Refresh();
        StatusMessage = $"Schedule '{SelectedRow.Schedule.Name}' {(enabled ? "enabled" : "disabled")}.";
        return Task.CompletedTask;
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
            var agent = AgentFactory.Create(schedule.MachineRole).Agent;
            var result = await agent.RunAuditAsync(schedule.Intent, rawLog: null, cts.Token);
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
                await notifier.NotifyCriticalFindingsAsync(schedule.Name, criticalCount, cts.Token);
            }

            Dispatcher.UIThread.Post(() =>
            {
                StatusMessage = $"'{schedule.Name}' completed. {criticalCount} critical finding(s).";
            });
        });
    }

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

    private INotificationService CreateNotificationService(NotificationChannel channel)
    {
        return channel switch
        {
            NotificationChannel.Email => CreateEmailService(),
            NotificationChannel.Webhook => CreateWebhookService(),
            _ => _fallbackNotificationService
        };
    }

    private static INotificationService CreateEmailService()
    {
        var host = Environment.GetEnvironmentVariable("VT_EMAIL_SMTP_HOST") ?? "localhost";
        var port = int.TryParse(Environment.GetEnvironmentVariable("VT_EMAIL_SMTP_PORT"), out var p) ? p : 587;
        var fromAddr = Environment.GetEnvironmentVariable("VT_EMAIL_FROM") ?? "vulcanstrace@localhost";
        var toAddr = Environment.GetEnvironmentVariable("VT_EMAIL_TO") ?? "admin@localhost";
        var user = Environment.GetEnvironmentVariable("VT_EMAIL_USER");
        var pass = Environment.GetEnvironmentVariable("VT_EMAIL_PASS");
        var noSsl = Environment.GetEnvironmentVariable("VT_EMAIL_NO_SSL");
        var disableSsl = noSsl?.Equals("1", StringComparison.OrdinalIgnoreCase) == true
            || noSsl?.Equals("true", StringComparison.OrdinalIgnoreCase) == true
            || noSsl?.Equals("yes", StringComparison.OrdinalIgnoreCase) == true;
        var enableSsl = !disableSsl;
        return new EmailNotificationService(host, port, fromAddr, toAddr, user, pass, enableSsl);
    }

    private static INotificationService CreateWebhookService()
    {
        var url = Environment.GetEnvironmentVariable("VT_WEBHOOK_URL") ?? "http://localhost:8080/webhook";
        return new WebhookNotificationService(url);
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
