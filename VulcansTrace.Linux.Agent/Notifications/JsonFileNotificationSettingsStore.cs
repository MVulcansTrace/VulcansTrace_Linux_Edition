using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// A file-backed notification settings store using JSON persistence.
/// </summary>
public sealed class JsonFileNotificationSettingsStore : INotificationSettingsStore
{
    private const UnixFileMode SecretFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // Serialize the channel as a readable string ("Email") instead of a magic number (1) so the
        // settings file is hand-editable; JsonStringEnumConverter still reads numeric values too.
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly JsonFilePersistence<NotificationSettings> _persistence;
    private NotificationSettings _settings;
    private string? _persistenceWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileNotificationSettingsStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileNotificationSettingsStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<NotificationSettings>(
            filePath,
            JsonOptions,
            unixFileMode: SecretFileMode,
            logSink: logSink);
        _settings = LoadSettings();
    }

    /// <summary>
    /// Creates a store in the user's config directory.
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFileNotificationSettingsStore"/>.</returns>
    public static JsonFileNotificationSettingsStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        ApplySecureDirectoryMode(dir);
        return new JsonFileNotificationSettingsStore(Path.Combine(dir, "notification-settings.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    /// <inheritdoc />
    public NotificationSettings Settings
    {
        get => _settings;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _settings = value;
            try
            {
                _persistence.Save(value);
                _persistenceWarning = null;
            }
            catch (Exception ex)
            {
                _persistenceWarning = $"Could not save notification settings to disk: {ex.Message}. Settings will last only for this session.";
            }
        }
    }

    private NotificationSettings LoadSettings()
    {
        try
        {
            var loaded = _persistence.Load();
            if (loaded != null)
            {
                _persistenceWarning = null;
                return loaded;
            }
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load notification settings; defaults will be used. {ex.Message}";
        }

        return new NotificationSettings();
    }

    private static void ApplySecureDirectoryMode(string directory)
    {
        if (OperatingSystem.IsWindows())
            return;

        File.SetUnixFileMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
}
