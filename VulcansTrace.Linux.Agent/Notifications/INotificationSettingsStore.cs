namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Persistence store for global notification settings.
/// </summary>
public interface INotificationSettingsStore
{
    /// <summary>Gets or saves the current notification settings.</summary>
    NotificationSettings Settings { get; set; }

    /// <summary>Warning message if persistence is unavailable.</summary>
    string? PersistenceWarning { get; }
}
