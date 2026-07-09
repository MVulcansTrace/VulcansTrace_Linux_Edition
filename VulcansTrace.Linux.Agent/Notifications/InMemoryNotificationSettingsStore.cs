namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// An in-memory notification settings store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryNotificationSettingsStore : INotificationSettingsStore
{
    private NotificationSettings _settings = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryNotificationSettingsStore"/> class.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning shown when persistence is unavailable.</param>
    public InMemoryNotificationSettingsStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public NotificationSettings Settings
    {
        get => _settings;
        set => _settings = value ?? throw new ArgumentNullException(nameof(value));
    }
}
