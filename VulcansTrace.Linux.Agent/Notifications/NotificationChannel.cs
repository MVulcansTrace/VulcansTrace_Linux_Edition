namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Defines the available notification channels for scheduled audit alerts.
/// </summary>
public enum NotificationChannel
{
    /// <summary>Linux desktop toast via notify-send.</summary>
    Desktop,

    /// <summary>Email via SMTP.</summary>
    Email,

    /// <summary>HTTP webhook POST.</summary>
    Webhook
}
