using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// Configuration for a single recurring audit schedule.
/// </summary>
public sealed record AuditSchedule
{
    /// <summary>Unique identifier for this schedule.</summary>
    public required string Id { get; init; }

    /// <summary>User-friendly name.</summary>
    public required string Name { get; init; }

    /// <summary>The audit intent to execute.</summary>
    public required AgentIntent Intent { get; init; }

    /// <summary>Cron expression (e.g. <c>0 6 * * 1</c> for weekly Monday 06:00).</summary>
    public required string CronExpression { get; init; }

    /// <summary>The machine role used when running this schedule.</summary>
    public MachineRole MachineRole { get; init; } = MachineRole.Workstation;

    /// <summary>Whether the schedule is active.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Send a notification when new critical findings appear.</summary>
    public bool NotifyOnCritical { get; init; } = true;

    /// <summary>The notification channel to use for critical alerts.</summary>
    public NotificationChannel NotificationChannel { get; init; } = NotificationChannel.Desktop;

    /// <summary>Optional directory to write JSON audit results.</summary>
    public string? OutputDirectory { get; init; }

    /// <summary>UTC timestamp of the last execution, if any.</summary>
    public DateTime? LastRunUtc { get; init; }

    /// <summary>UTC timestamp when the schedule was created.</summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}
