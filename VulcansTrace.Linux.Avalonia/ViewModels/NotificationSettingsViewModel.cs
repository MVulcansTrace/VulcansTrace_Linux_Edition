using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Notifications;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for configuring global notification channel settings.
/// </summary>
public sealed class NotificationSettingsViewModel : ViewModelBase
{
    private readonly INotificationSettingsStore _store;
    private readonly Func<NotificationSettings, INotificationService> _serviceFactory;
    private readonly AnalystActionLogger? _analystActionLogger;
    private string _statusMessage = "";
    private bool _isTesting;
    private NotificationChannel _selectedChannel;
    private bool _enabled;
    private string _emailSmtpHost = "localhost";
    private int _emailSmtpPort = 587;
    private string _emailFrom = "vulcanstrace@localhost";
    private string _emailTo = "admin@localhost";
    private string _emailUsername = "";
    private string _emailPassword = "";
    private bool _emailEnableSsl = true;
    private string _webhookUrl = "http://localhost:8080/webhook";

    /// <summary>Gets the available notification channels.</summary>
    public ObservableCollection<NotificationChannel> AvailableChannels { get; } = new();

    /// <summary>Gets or sets the selected notification channel.</summary>
    public NotificationChannel SelectedChannel
    {
        get => _selectedChannel;
        set
        {
            if (SetField(ref _selectedChannel, value))
            {
                OnPropertyChanged(nameof(IsDesktopSelected));
                OnPropertyChanged(nameof(IsEmailSelected));
                OnPropertyChanged(nameof(IsWebhookSelected));
            }
        }
    }

    /// <summary>Gets or sets whether notifications are enabled globally.</summary>
    public bool Enabled
    {
        get => _enabled;
        set
        {
            if (SetField(ref _enabled, value))
            {
                // TestCommand.CanExecute depends on Enabled, so bound buttons must re-query.
                TestCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets a value indicating whether Desktop is the selected channel.</summary>
    public bool IsDesktopSelected => _selectedChannel == NotificationChannel.Desktop;

    /// <summary>Gets a value indicating whether Email is the selected channel.</summary>
    public bool IsEmailSelected => _selectedChannel == NotificationChannel.Email;

    /// <summary>Gets a value indicating whether Webhook is the selected channel.</summary>
    public bool IsWebhookSelected => _selectedChannel == NotificationChannel.Webhook;

    /// <summary>Gets or sets the SMTP host.</summary>
    public string EmailSmtpHost
    {
        get => _emailSmtpHost;
        set => SetField(ref _emailSmtpHost, value);
    }

    /// <summary>Gets or sets the SMTP port.</summary>
    public int EmailSmtpPort
    {
        get => _emailSmtpPort;
        set => SetField(ref _emailSmtpPort, value);
    }

    /// <summary>Gets or sets the sender email address.</summary>
    public string EmailFrom
    {
        get => _emailFrom;
        set => SetField(ref _emailFrom, value);
    }

    /// <summary>Gets or sets the recipient email address.</summary>
    public string EmailTo
    {
        get => _emailTo;
        set => SetField(ref _emailTo, value);
    }

    /// <summary>Gets or sets the SMTP username.</summary>
    public string EmailUsername
    {
        get => _emailUsername;
        set => SetField(ref _emailUsername, value);
    }

    /// <summary>Gets or sets the SMTP password.</summary>
    public string EmailPassword
    {
        get => _emailPassword;
        set => SetField(ref _emailPassword, value);
    }

    /// <summary>Gets or sets whether to enable SSL/TLS for SMTP.</summary>
    public bool EmailEnableSsl
    {
        get => _emailEnableSsl;
        set => SetField(ref _emailEnableSsl, value);
    }

    /// <summary>Gets or sets the webhook URL.</summary>
    public string WebhookUrl
    {
        get => _webhookUrl;
        set => SetField(ref _webhookUrl, value);
    }

    /// <summary>Gets or sets a status message describing the last action.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Gets whether a test notification is in progress.</summary>
    public bool IsTesting
    {
        get => _isTesting;
        private set
        {
            if (SetField(ref _isTesting, value))
            {
                TestCommand.RaiseCanExecuteChanged();
                SaveCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets the command to save notification settings.</summary>
    public AsyncRelayCommand SaveCommand { get; }

    /// <summary>Gets the command to send a test notification.</summary>
    public AsyncRelayCommand TestCommand { get; }

    /// <summary>Gets the command to reset the form to the stored settings.</summary>
    public RelayCommand ResetCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="NotificationSettingsViewModel"/> class.
    /// </summary>
    /// <param name="store">The notification settings store.</param>
    /// <param name="notificationServiceFactory">
    /// Optional factory that builds a notification service from settings, used by the Test command.
    /// Defaults to <see cref="NotificationChannelExtensions.CreateNotificationService"/>; tests may
    /// inject a stub to make Test outcomes deterministic.
    /// </param>
    /// <param name="analystActionLogger">Optional analyst action logger.</param>
    public NotificationSettingsViewModel(
        INotificationSettingsStore store,
        Func<NotificationSettings, INotificationService>? notificationServiceFactory = null,
        AnalystActionLogger? analystActionLogger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _serviceFactory = notificationServiceFactory ?? NotificationChannelExtensions.CreateNotificationService;
        _analystActionLogger = analystActionLogger;

        foreach (NotificationChannel channel in Enum.GetValues(typeof(NotificationChannel)))
        {
            AvailableChannels.Add(channel);
        }

        SaveCommand = new AsyncRelayCommand(
            async _ => await SaveAsync(),
            _ => !IsTesting,
            ex => StatusMessage = $"Save failed: {ErrorSanitizer.SanitizeException(ex)}");

        TestCommand = new AsyncRelayCommand(
            async _ => await TestAsync(),
            _ => !IsTesting && Enabled,
            ex => StatusMessage = $"Test failed: {ErrorSanitizer.SanitizeException(ex)}");

        ResetCommand = new RelayCommand(
            _ => LoadSettings(),
            _ => !IsTesting);

        LoadSettings();
    }

    /// <summary>
    /// Loads settings from the store into the ViewModel.
    /// </summary>
    public void LoadSettings()
    {
        var settings = _store.Settings;
        SelectedChannel = settings.Channel;
        Enabled = settings.Enabled;
        EmailSmtpHost = settings.EmailSmtpHost;
        EmailSmtpPort = settings.EmailSmtpPort;
        EmailFrom = settings.EmailFrom;
        EmailTo = settings.EmailTo;
        EmailUsername = settings.EmailUsername ?? "";
        EmailPassword = settings.EmailPassword ?? "";
        EmailEnableSsl = settings.EmailEnableSsl;
        WebhookUrl = settings.WebhookUrl;
        StatusMessage = _store.PersistenceWarning ?? "Notification settings loaded.";
    }

    /// <summary>
    /// Builds a <see cref="NotificationSettings"/> from the current ViewModel values.
    /// </summary>
    public NotificationSettings ToSettings()
    {
        return new NotificationSettings
        {
            Channel = _selectedChannel,
            Enabled = _enabled,
            EmailSmtpHost = _emailSmtpHost,
            EmailSmtpPort = _emailSmtpPort,
            EmailFrom = _emailFrom,
            EmailTo = _emailTo,
            EmailUsername = string.IsNullOrWhiteSpace(_emailUsername) ? null : _emailUsername,
            EmailPassword = string.IsNullOrWhiteSpace(_emailPassword) ? null : _emailPassword,
            EmailEnableSsl = _emailEnableSsl,
            WebhookUrl = _webhookUrl
        };
    }

    private async Task SaveAsync()
    {
        var settings = ToSettings();
        _store.Settings = settings;
        StatusMessage = _store.PersistenceWarning ?? "Notification settings saved.";
        if (_analystActionLogger is { } actionLogger)
        {
            await actionLogger.LogNotificationSettingsChangedAsync("avalonia", settings.Channel.ToString());
        }
        await Task.CompletedTask;
    }

    private async Task TestAsync()
    {
        IsTesting = true;
        try
        {
            var settings = ToSettings();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var service = _serviceFactory(settings);
            try
            {
                // SendTestAsync surfaces real delivery success/failure (unlike the Notify* methods,
                // which swallow errors so a notification can never break an audit).
                var delivered = await service.SendTestAsync(cts.Token);
                StatusMessage = delivered
                    ? "Test notification delivered."
                    : "Test notification could not be delivered — check the channel settings (delivery errors are logged to stderr).";
            }
            finally
            {
                (service as IDisposable)?.Dispose();
            }
        }
        finally
        {
            IsTesting = false;
        }
    }
}
