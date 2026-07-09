using System;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class NotificationSettingsViewModelTests
{
    [AvaloniaFact]
    public void LoadSettings_LoadsDefaultsFromStore()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store);

        Assert.True(vm.Enabled);
        Assert.Equal(NotificationChannel.Desktop, vm.SelectedChannel);
        Assert.Equal("localhost", vm.EmailSmtpHost);
        Assert.Equal(587, vm.EmailSmtpPort);
    }

    [AvaloniaFact]
    public void LoadSettings_LoadsCustomSettingsFromStore()
    {
        var store = new InMemoryNotificationSettingsStore
        {
            Settings = new NotificationSettings
            {
                Channel = NotificationChannel.Email,
                Enabled = false,
                EmailSmtpHost = "smtp.example.com",
                EmailSmtpPort = 465,
                EmailFrom = "from@example.com",
                EmailTo = "to@example.com",
                EmailUsername = "user",
                EmailPassword = "pass",
                EmailEnableSsl = false,
                WebhookUrl = "https://example.com/webhook"
            }
        };

        var vm = new NotificationSettingsViewModel(store);

        Assert.False(vm.Enabled);
        Assert.Equal(NotificationChannel.Email, vm.SelectedChannel);
        Assert.Equal("smtp.example.com", vm.EmailSmtpHost);
        Assert.Equal(465, vm.EmailSmtpPort);
        Assert.Equal("from@example.com", vm.EmailFrom);
        Assert.Equal("to@example.com", vm.EmailTo);
        Assert.Equal("user", vm.EmailUsername);
        Assert.Equal("pass", vm.EmailPassword);
        Assert.False(vm.EmailEnableSsl);
        Assert.Equal("https://example.com/webhook", vm.WebhookUrl);
    }

    [AvaloniaFact]
    public async Task SaveCommand_PersistsSettingsToStore()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store)
        {
            SelectedChannel = NotificationChannel.Webhook,
            Enabled = false,
            WebhookUrl = "https://hooks.example.com/vt"
        };

        vm.SaveCommand.Execute(null);
        await ((AsyncRelayCommand)vm.SaveCommand).ExecutionTask;

        Assert.Equal(NotificationChannel.Webhook, store.Settings.Channel);
        Assert.False(store.Settings.Enabled);
        Assert.Equal("https://hooks.example.com/vt", store.Settings.WebhookUrl);
        Assert.Contains("saved", vm.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public async Task TestCommand_WhenDeliverySucceeds_ReportsDelivered()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store, _ => new StubNotificationService(delivers: true));

        vm.TestCommand.Execute(null);
        await ((AsyncRelayCommand)vm.TestCommand).ExecutionTask;

        Assert.Contains("delivered", vm.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public async Task TestCommand_WhenDeliveryFails_ReportsFailure()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store, _ => new StubNotificationService(delivers: false));

        vm.TestCommand.Execute(null);
        await ((AsyncRelayCommand)vm.TestCommand).ExecutionTask;

        Assert.Contains("could not be delivered", vm.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public async Task TestCommand_DisposesDisposableService()
    {
        var store = new InMemoryNotificationSettingsStore();
        var service = new DisposableStubNotificationService(delivers: true);
        var vm = new NotificationSettingsViewModel(store, _ => service);

        vm.TestCommand.Execute(null);
        await ((AsyncRelayCommand)vm.TestCommand).ExecutionTask;

        Assert.True(service.IsDisposed);
    }

    [AvaloniaFact]
    public void ToSettings_RoundTripsValues()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store)
        {
            SelectedChannel = NotificationChannel.Email,
            Enabled = true,
            EmailSmtpHost = "mail.example.com",
            EmailSmtpPort = 25,
            EmailFrom = "a@example.com",
            EmailTo = "b@example.com",
            EmailUsername = "u",
            EmailPassword = "p",
            EmailEnableSsl = true,
            WebhookUrl = "http://example.com/hook"
        };

        var settings = vm.ToSettings();

        Assert.Equal(NotificationChannel.Email, settings.Channel);
        Assert.True(settings.Enabled);
        Assert.Equal("mail.example.com", settings.EmailSmtpHost);
        Assert.Equal(25, settings.EmailSmtpPort);
        Assert.Equal("a@example.com", settings.EmailFrom);
        Assert.Equal("b@example.com", settings.EmailTo);
        Assert.Equal("u", settings.EmailUsername);
        Assert.Equal("p", settings.EmailPassword);
        Assert.True(settings.EmailEnableSsl);
        Assert.Equal("http://example.com/hook", settings.WebhookUrl);
    }

    [AvaloniaFact]
    public void ResetCommand_RestoresOriginalSettings()
    {
        var store = new InMemoryNotificationSettingsStore
        {
            Settings = new NotificationSettings { Channel = NotificationChannel.Webhook, WebhookUrl = "https://original.example.com" }
        };
        var vm = new NotificationSettingsViewModel(store)
        {
            SelectedChannel = NotificationChannel.Email,
            WebhookUrl = "https://changed.example.com"
        };

        vm.ResetCommand.Execute(null);

        Assert.Equal(NotificationChannel.Webhook, vm.SelectedChannel);
        Assert.Equal("https://original.example.com", vm.WebhookUrl);
    }

    [AvaloniaFact]
    public void Enabled_TogglesRaiseTestCommandCanExecuteChanged()
    {
        var store = new InMemoryNotificationSettingsStore();
        var vm = new NotificationSettingsViewModel(store);

        var raises = 0;
        vm.TestCommand.CanExecuteChanged += (_, _) => raises++;
        raises = 0; // discard the subscribe-time invocation

        vm.Enabled = false;

        Assert.Equal(1, raises); // bound Test button must re-query when Enable is toggled
        Assert.False(vm.TestCommand.CanExecute(null));
    }

    private sealed class StubNotificationService : INotificationService
    {
        private readonly bool _delivers;

        public StubNotificationService(bool delivers) => _delivers = delivers;

        public Task NotifyAsync(string title, string message, CancellationToken ct = default) => Task.CompletedTask;
        public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default) => Task.CompletedTask;
        public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> SendTestAsync(CancellationToken ct = default) => Task.FromResult(_delivers);
    }

    private sealed class DisposableStubNotificationService : INotificationService, IDisposable
    {
        private readonly bool _delivers;
        public bool IsDisposed { get; private set; }

        public DisposableStubNotificationService(bool delivers) => _delivers = delivers;

        public Task NotifyAsync(string title, string message, CancellationToken ct = default) => Task.CompletedTask;
        public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default) => Task.CompletedTask;
        public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default) => Task.CompletedTask;
        public Task<bool> SendTestAsync(CancellationToken ct = default) => Task.FromResult(_delivers);
        public void Dispose() => IsDisposed = true;
    }
}
