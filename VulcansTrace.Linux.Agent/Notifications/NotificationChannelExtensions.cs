namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Extension methods for notification channel configuration.
/// </summary>
public static class NotificationChannelExtensions
{
    /// <summary>
    /// Creates a notification service configured from global notification settings.
    /// </summary>
    public static INotificationService CreateNotificationService(this NotificationSettings settings)
        => settings.CreateNotificationService(settings.Channel);

    /// <summary>
    /// Creates a notification service from global settings, using a schedule-selected channel.
    /// </summary>
    /// <param name="settings">Global notification settings containing enabled state and channel-specific options.</param>
    /// <param name="channel">The notification channel selected by a schedule or command.</param>
    /// <param name="desktopService">Optional desktop service instance to use for desktop notifications.</param>
    /// <returns>A notification service for the selected channel.</returns>
    public static INotificationService CreateNotificationService(
        this NotificationSettings settings,
        NotificationChannel channel,
        INotificationService? desktopService = null)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!settings.Enabled)
            return new NullNotificationService();

        return channel switch
        {
            NotificationChannel.Email => new EmailNotificationService(settings),
            NotificationChannel.Webhook => new WebhookNotificationService(settings),
            _ => desktopService ?? new NotifySendNotificationService()
        };
    }

    /// <summary>
    /// Returns the display label for a notification channel.
    /// </summary>
    public static string GetLabel(this NotificationChannel channel) => channel switch
    {
        NotificationChannel.Email => "Email (SMTP)",
        NotificationChannel.Webhook => "Webhook (HTTP POST)",
        _ => "Desktop (notify-send)"
    };
}

/// <summary>
/// A no-op notification service used when notifications are disabled.
/// </summary>
public sealed class NullNotificationService : INotificationService
{
    /// <inheritdoc />
    [Obsolete("Unused - prefer NotifyCriticalFindingsAsync")]
    public Task NotifyAsync(string title, string message, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <inheritdoc />
    public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <inheritdoc />
    public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <inheritdoc />
    public Task<bool> SendTestAsync(CancellationToken ct = default) => Task.FromResult(false);
}
