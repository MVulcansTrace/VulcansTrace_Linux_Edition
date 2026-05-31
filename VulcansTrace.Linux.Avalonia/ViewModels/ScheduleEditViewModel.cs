using System;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the schedule add/edit dialog.
/// </summary>
public sealed class ScheduleEditViewModel : ViewModelBase
{
    private string _name = "";
    private AgentIntent _intent = AgentIntent.FullAudit;
    private string _cronExpression = "";
    private MachineRole _machineRole = MachineRole.Workstation;
    private string? _outputDirectory;
    private bool _notifyOnCritical = true;
    private bool _enabled = true;
    private NotificationChannel _notificationChannel = NotificationChannel.Desktop;
    private DateTime? _lastRunUtc;
    private DateTime _createdAtUtc = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the schedule name.
    /// </summary>
    public string Name
    {
        get => _name;
        set => SetField(ref _name, value);
    }

    /// <summary>
    /// Gets or sets the audit intent.
    /// </summary>
    public AgentIntent Intent
    {
        get => _intent;
        set => SetField(ref _intent, value);
    }

    /// <summary>
    /// Gets or sets the cron expression.
    /// </summary>
    public string CronExpression
    {
        get => _cronExpression;
        set => SetField(ref _cronExpression, value);
    }

    /// <summary>
    /// Gets or sets the machine role.
    /// </summary>
    public MachineRole MachineRole
    {
        get => _machineRole;
        set => SetField(ref _machineRole, value);
    }

    /// <summary>
    /// Gets or sets the output directory.
    /// </summary>
    public string? OutputDirectory
    {
        get => _outputDirectory;
        set => SetField(ref _outputDirectory, value);
    }

    /// <summary>
    /// Gets or sets whether to notify on critical findings.
    /// </summary>
    public bool NotifyOnCritical
    {
        get => _notifyOnCritical;
        set => SetField(ref _notifyOnCritical, value);
    }

    /// <summary>
    /// Gets or sets the notification channel for critical alerts.
    /// </summary>
    public NotificationChannel NotificationChannel
    {
        get => _notificationChannel;
        set => SetField(ref _notificationChannel, value);
    }

    /// <summary>
    /// Gets or sets whether the schedule is enabled.
    /// </summary>
    public bool Enabled
    {
        get => _enabled;
        set => SetField(ref _enabled, value);
    }

    /// <summary>Available audit intents.</summary>
    public AgentIntent[] AvailableIntents { get; } = Enum.GetValues<AgentIntent>();

    /// <summary>Available machine roles.</summary>
    public MachineRole[] AvailableRoles { get; } = Enum.GetValues<MachineRole>();

    /// <summary>Available notification channels.</summary>
    public NotificationChannel[] AvailableChannels { get; } = Enum.GetValues<NotificationChannel>();

    /// <summary>
    /// Loads an existing schedule into this ViewModel.
    /// </summary>
    public void LoadSchedule(AuditSchedule schedule)
    {
        Name = schedule.Name;
        Intent = schedule.Intent;
        CronExpression = schedule.CronExpression;
        MachineRole = schedule.MachineRole;
        OutputDirectory = schedule.OutputDirectory;
        NotifyOnCritical = schedule.NotifyOnCritical;
        NotificationChannel = schedule.NotificationChannel;
        Enabled = schedule.Enabled;
        _lastRunUtc = schedule.LastRunUtc;
        _createdAtUtc = schedule.CreatedAtUtc;
    }

    /// <summary>
    /// Creates a new schedule record from the current values.
    /// </summary>
    public AuditSchedule ToSchedule(string? id = null)
    {
        return new AuditSchedule
        {
            Id = id ?? Guid.NewGuid().ToString("N"),
            Name = Name.Trim(),
            Intent = Intent,
            CronExpression = CronExpression.Trim(),
            MachineRole = MachineRole,
            OutputDirectory = string.IsNullOrWhiteSpace(OutputDirectory) ? null : OutputDirectory.Trim(),
            NotifyOnCritical = NotifyOnCritical,
            NotificationChannel = NotificationChannel,
            Enabled = Enabled,
            LastRunUtc = _lastRunUtc,
            CreatedAtUtc = _createdAtUtc
        };
    }
}
