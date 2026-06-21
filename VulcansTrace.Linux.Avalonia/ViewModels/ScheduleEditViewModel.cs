using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Core;

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
    private bool _autonomousDriftResponse = false;
    private Severity _autonomousDriftSeverityThreshold = Severity.High;
    private bool _requireSignedAlerts = false;
    private bool _allowAutoRemediate = false;
    private bool _allowRemediationRestart = false;
    private bool _allowRemediationPackages = false;
    private string _remediationPrefixes = "";
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

    /// <summary>
    /// Gets or sets whether to autonomously respond to baseline drift.
    /// </summary>
    public bool AutonomousDriftResponse
    {
        get => _autonomousDriftResponse;
        set => SetField(ref _autonomousDriftResponse, value);
    }

    /// <summary>
    /// Gets or sets the severity threshold for autonomous drift alerts.
    /// </summary>
    public Severity AutonomousDriftSeverityThreshold
    {
        get => _autonomousDriftSeverityThreshold;
        set => SetField(ref _autonomousDriftSeverityThreshold, value);
    }

    /// <summary>
    /// Gets or sets whether drift alerts must be cryptographically signed (fail closed when no signing key is set).
    /// </summary>
    public bool RequireSignedAlerts
    {
        get => _requireSignedAlerts;
        set => SetField(ref _requireSignedAlerts, value);
    }

    /// <summary>Available audit intents.</summary>
    public AgentIntent[] AvailableIntents { get; } = Enum.GetValues<AgentIntent>();

    /// <summary>Available machine roles.</summary>
    public MachineRole[] AvailableRoles { get; } = Enum.GetValues<MachineRole>();

    /// <summary>Available notification channels.</summary>
    public NotificationChannel[] AvailableChannels { get; } = Enum.GetValues<NotificationChannel>();

    /// <summary>Available severity thresholds.</summary>
    public Severity[] AvailableSeverities { get; } = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info };

    /// <summary>
    /// Gets or sets whether human-approved remediation is enabled for this schedule.
    /// </summary>
    public bool AllowAutoRemediate
    {
        get => _allowAutoRemediate;
        set => SetField(ref _allowAutoRemediate, value);
    }

    /// <summary>
    /// Gets or sets whether remediation may restart services.
    /// </summary>
    public bool AllowRemediationRestart
    {
        get => _allowRemediationRestart;
        set => SetField(ref _allowRemediationRestart, value);
    }

    /// <summary>
    /// Gets or sets whether remediation may install or remove packages.
    /// </summary>
    public bool AllowRemediationPackages
    {
        get => _allowRemediationPackages;
        set => SetField(ref _allowRemediationPackages, value);
    }

    /// <summary>
    /// Gets or sets the comma-separated rule-id prefixes remediation may target.
    /// </summary>
    public string RemediationPrefixes
    {
        get => _remediationPrefixes;
        set => SetField(ref _remediationPrefixes, value);
    }

    /// <summary>Example rule prefixes for remediation scoping.</summary>
    public string[] AvailableRulePrefixes { get; } = new[] { "FW", "KERN", "PKG", "SSH", "USER", "FILE", "LOG", "CRON", "CONTAINER", "K8S", "PROCESS" };

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
        AutonomousDriftResponse = schedule.AutonomousDriftResponse;
        AutonomousDriftSeverityThreshold = schedule.AutonomousDriftSeverityThreshold;
        RequireSignedAlerts = schedule.RequireSignedAlerts;
        AllowAutoRemediate = schedule.AllowAutoRemediate;
        AllowRemediationRestart = schedule.AllowRemediationRestart;
        AllowRemediationPackages = schedule.AllowRemediationPackages;
        RemediationPrefixes = string.Join(", ", schedule.AllowedRemediationRulePrefixes ?? Array.Empty<string>());
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
            AutonomousDriftResponse = AutonomousDriftResponse,
            AutonomousDriftSeverityThreshold = AutonomousDriftSeverityThreshold,
            RequireSignedAlerts = RequireSignedAlerts,
            AllowAutoRemediate = AllowAutoRemediate,
            AllowRemediationRestart = AllowRemediationRestart,
            AllowRemediationPackages = AllowRemediationPackages,
            AllowedRemediationRulePrefixes = ParseRemediationPrefixes(RemediationPrefixes),
            Enabled = Enabled,
            LastRunUtc = _lastRunUtc,
            CreatedAtUtc = _createdAtUtc
        };
    }

    private static IReadOnlyList<string> ParseRemediationPrefixes(string value)
        => RemediationScopeFilter.ParsePrefixes(value);
}
