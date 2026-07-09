namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Global notification channel configuration for the VulcansTrace agent and UI.
/// </summary>
public sealed record NotificationSettings
{
    /// <summary>The active notification channel.</summary>
    public NotificationChannel Channel { get; init; } = NotificationChannel.Desktop;

    /// <summary>SMTP host for email notifications.</summary>
    public string EmailSmtpHost { get; init; } = "localhost";

    /// <summary>SMTP port for email notifications.</summary>
    public int EmailSmtpPort { get; init; } = 587;

    /// <summary>Sender email address.</summary>
    public string EmailFrom { get; init; } = "vulcanstrace@localhost";

    /// <summary>Default recipient email address.</summary>
    public string EmailTo { get; init; } = "admin@localhost";

    /// <summary>SMTP username (optional).</summary>
    public string? EmailUsername { get; init; }

    /// <summary>SMTP password (optional).</summary>
    public string? EmailPassword { get; init; }

    /// <summary>Whether to enable SSL/TLS for SMTP.</summary>
    public bool EmailEnableSsl { get; init; } = true;

    /// <summary>Webhook URL for HTTP notifications.</summary>
    public string WebhookUrl { get; init; } = "http://localhost:8080/webhook";

    /// <summary>Whether notifications are enabled globally.</summary>
    public bool Enabled { get; init; } = true;
}
