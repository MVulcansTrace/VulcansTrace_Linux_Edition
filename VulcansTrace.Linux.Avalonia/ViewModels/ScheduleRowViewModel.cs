using System;
using VulcansTrace.Linux.Agent.Scheduling;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Wrapper around <see cref="AuditSchedule"/> for UI display that adds transient properties.
/// </summary>
public sealed class ScheduleRowViewModel : ViewModelBase
{
    private AuditSchedule _schedule;
    private bool _isInstalledInCron;

    /// <summary>
    /// Initializes a new instance of the <see cref="ScheduleRowViewModel"/> class.
    /// </summary>
    public ScheduleRowViewModel(AuditSchedule schedule)
    {
        _schedule = schedule;
    }

    /// <summary>
    /// Gets or sets the underlying schedule.
    /// </summary>
    public AuditSchedule Schedule
    {
        get => _schedule;
        set
        {
            if (SetField(ref _schedule, value))
            {
                OnPropertyChanged(nameof(Name));
                OnPropertyChanged(nameof(Intent));
                OnPropertyChanged(nameof(MachineRole));
                OnPropertyChanged(nameof(CronExpression));
                OnPropertyChanged(nameof(Enabled));
                OnPropertyChanged(nameof(NotifyOnCritical));
                OnPropertyChanged(nameof(NotificationChannel));
                OnPropertyChanged(nameof(OutputDirectory));
                OnPropertyChanged(nameof(LastRunUtc));
                OnPropertyChanged(nameof(AutonomousDriftResponse));
                OnPropertyChanged(nameof(AutonomousDriftSeverityThreshold));
                OnPropertyChanged(nameof(AllowAutoRemediate));
                OnPropertyChanged(nameof(AllowRemediationRestart));
                OnPropertyChanged(nameof(AllowRemediationPackages));
                OnPropertyChanged(nameof(AllowedRemediationPrefixes));
            }
        }
    }

    /// <summary>Gets whether this schedule has a crontab entry installed.</summary>
    public bool IsInstalledInCron
    {
        get => _isInstalledInCron;
        set => SetField(ref _isInstalledInCron, value);
    }

    /// <summary>Proxy for schedule name.</summary>
    public string Name => _schedule.Name;

    /// <summary>Proxy for schedule intent.</summary>
    public string Intent => _schedule.Intent.ToString();

    /// <summary>Proxy for schedule machine role.</summary>
    public string MachineRole => _schedule.MachineRole.ToString();

    /// <summary>Proxy for schedule cron expression.</summary>
    public string CronExpression => _schedule.CronExpression;

    /// <summary>Proxy for schedule enabled state.</summary>
    public bool Enabled => _schedule.Enabled;

    /// <summary>Proxy for schedule notify flag.</summary>
    public bool NotifyOnCritical => _schedule.NotifyOnCritical;

    /// <summary>Proxy for schedule notification channel.</summary>
    public string NotificationChannel => _schedule.NotificationChannel.ToString();

    /// <summary>Proxy for schedule output directory.</summary>
    public string? OutputDirectory => _schedule.OutputDirectory;

    /// <summary>Proxy for schedule last run time.</summary>
    public DateTime? LastRunUtc => _schedule.LastRunUtc;

    /// <summary>Proxy for schedule autonomous drift response flag.</summary>
    public bool AutonomousDriftResponse => _schedule.AutonomousDriftResponse;

    /// <summary>Proxy for schedule autonomous drift severity threshold.</summary>
    public string AutonomousDriftSeverityThreshold => _schedule.AutonomousDriftSeverityThreshold.ToString();

    /// <summary>Proxy for schedule allow auto-remediate flag.</summary>
    public bool AllowAutoRemediate => _schedule.AllowAutoRemediate;

    /// <summary>Proxy for whether remediation may restart services.</summary>
    public bool AllowRemediationRestart => _schedule.AllowRemediationRestart;

    /// <summary>Proxy for whether remediation may install or remove packages.</summary>
    public bool AllowRemediationPackages => _schedule.AllowRemediationPackages;

    /// <summary>Proxy for the comma-separated remediation rule-prefix scope.</summary>
    public string AllowedRemediationPrefixes => string.Join(", ", _schedule.AllowedRemediationRulePrefixes);
}
