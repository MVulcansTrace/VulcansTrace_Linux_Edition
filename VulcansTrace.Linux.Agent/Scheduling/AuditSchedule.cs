using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;

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

    /// <summary>Whether to autonomously respond to baseline drift on scheduled runs.</summary>
    public bool AutonomousDriftResponse { get; init; } = false;

    /// <summary>Severity threshold that must be met or exceeded before an autonomous drift alert is sent.</summary>
    public Severity AutonomousDriftSeverityThreshold { get; init; } = Severity.High;

    /// <summary>
    /// When true, drift alerts for this schedule are never sent unless they can be cryptographically
    /// signed (i.e. <c>VT_ALERT_SIGNING_KEY</c> is configured). Fail-closed for authenticity-sensitive
    /// deployments so an attacker who controls the notification channel cannot spoof UNSIGNED alerts.
    /// Also forced on by the <c>VT_REQUIRE_SIGNED_ALERTS</c> environment variable.
    /// </summary>
    public bool RequireSignedAlerts { get; init; } = false;

    /// <summary>Whether the schedule allows human-approved auto-remediation from drift alerts.</summary>
    public bool AllowAutoRemediate { get; init; } = false;

    /// <summary>Whether remediation for this schedule may restart services.</summary>
    public bool AllowRemediationRestart { get; init; } = false;

    /// <summary>Whether remediation for this schedule may install or remove packages.</summary>
    public bool AllowRemediationPackages { get; init; } = false;

    /// <summary>Optional rule-id prefixes (e.g. "FW", "KERN") that remediation may target. Empty means all.</summary>
    public IReadOnlyList<string> AllowedRemediationRulePrefixes { get; init; } = Array.Empty<string>();

    /// <summary>Optional directory to write JSON audit results.</summary>
    public string? OutputDirectory { get; init; }

    /// <summary>UTC timestamp of the last execution, if any.</summary>
    public DateTime? LastRunUtc { get; init; }

    /// <summary>UTC timestamp when the schedule was created.</summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}
