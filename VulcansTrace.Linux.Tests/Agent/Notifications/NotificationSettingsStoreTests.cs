using System.IO;
using VulcansTrace.Linux.Agent.Notifications;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Notifications;

public class NotificationSettingsStoreTests
{
    [Fact]
    public void JsonFileStore_Persistence_RoundTrip()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store1 = new JsonFileNotificationSettingsStore(path)
            {
                Settings = new NotificationSettings
                {
                    Channel = NotificationChannel.Email,
                    EmailSmtpHost = "smtp.example.com",
                    EmailSmtpPort = 465,
                    EmailFrom = "from@example.com",
                    EmailTo = "to@example.com"
                }
            };

            var store2 = new JsonFileNotificationSettingsStore(path);
            Assert.Equal(NotificationChannel.Email, store2.Settings.Channel);
            Assert.Equal("smtp.example.com", store2.Settings.EmailSmtpHost);
            Assert.Equal(465, store2.Settings.EmailSmtpPort);
            Assert.Equal("from@example.com", store2.Settings.EmailFrom);
            Assert.Equal("to@example.com", store2.Settings.EmailTo);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void JsonFileStore_CreateDefault_DoesNotThrow()
    {
        var tempConfigDir = Path.Combine(Path.GetTempPath(), $"vt-ns-test-{Guid.NewGuid():N}");
        try
        {
            var store = JsonFileNotificationSettingsStore.CreateDefault(tempConfigDir);
            Assert.NotNull(store);
            Assert.Equal(NotificationChannel.Desktop, store.Settings.Channel);
        }
        finally
        {
            try { if (Directory.Exists(tempConfigDir)) Directory.Delete(tempConfigDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void JsonFileStore_SaveFailure_KeepsSettingsForSessionAndWarns()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"vt-ns-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var path = Path.Combine(tempDir, "notification-settings.json");
        Directory.CreateDirectory(path);
        try
        {
            var store = new JsonFileNotificationSettingsStore(path);
            var settings = new NotificationSettings
            {
                Channel = NotificationChannel.Webhook,
                WebhookUrl = "https://hooks.example.com/session-only"
            };

            store.Settings = settings;

            Assert.Equal(NotificationChannel.Webhook, store.Settings.Channel);
            Assert.Equal("https://hooks.example.com/session-only", store.Settings.WebhookUrl);
            Assert.Contains("last only for this session", store.PersistenceWarning, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void JsonFileStore_PersistsWithOwnerOnlyMode_OnUnix()
    {
        if (OperatingSystem.IsWindows())
            return;

        var tempConfigDir = Path.Combine(Path.GetTempPath(), $"vt-ns-test-{Guid.NewGuid():N}");
        try
        {
            var store = JsonFileNotificationSettingsStore.CreateDefault(tempConfigDir);
            store.Settings = new NotificationSettings
            {
                Channel = NotificationChannel.Email,
                EmailPassword = "super-secret"
            };

            var path = Path.Combine(tempConfigDir, "VulcansTrace", "notification-settings.json");
            var mode = File.GetUnixFileMode(path);

            Assert.True(mode.HasFlag(UnixFileMode.UserRead));
            Assert.True(mode.HasFlag(UnixFileMode.UserWrite));
            Assert.False(mode.HasFlag(UnixFileMode.GroupRead));
            Assert.False(mode.HasFlag(UnixFileMode.GroupWrite));
            Assert.False(mode.HasFlag(UnixFileMode.OtherRead));
            Assert.False(mode.HasFlag(UnixFileMode.OtherWrite));
        }
        finally
        {
            try { if (Directory.Exists(tempConfigDir)) Directory.Delete(tempConfigDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void InMemoryStore_RoundTrip()
    {
        var store = new InMemoryNotificationSettingsStore();
        store.Settings = new NotificationSettings { Channel = NotificationChannel.Webhook, WebhookUrl = "https://example.com" };

        Assert.Equal(NotificationChannel.Webhook, store.Settings.Channel);
        Assert.Equal("https://example.com", store.Settings.WebhookUrl);
    }

    [Fact]
    public void CreateNotificationService_Disabled_ReturnsNullService()
    {
        var settings = new NotificationSettings { Enabled = false };
        var service = settings.CreateNotificationService();

        Assert.IsType<NullNotificationService>(service);
    }

    [Fact]
    public void CreateNotificationService_ScheduleChannel_UsesSelectedChannel()
    {
        var settings = new NotificationSettings { Channel = NotificationChannel.Desktop, EmailSmtpHost = "localhost" };
        var service = settings.CreateNotificationService(NotificationChannel.Email);

        Assert.IsType<EmailNotificationService>(service);
    }

    [Fact]
    public void CreateNotificationService_ScheduleChannel_RespectsGlobalDisable()
    {
        var settings = new NotificationSettings { Enabled = false, Channel = NotificationChannel.Email };
        var service = settings.CreateNotificationService(NotificationChannel.Webhook);

        Assert.IsType<NullNotificationService>(service);
    }

    [Fact]
    public void CreateNotificationService_Email_ReturnsEmailService()
    {
        var settings = new NotificationSettings { Channel = NotificationChannel.Email, EmailSmtpHost = "localhost" };
        var service = settings.CreateNotificationService();

        Assert.IsType<EmailNotificationService>(service);
    }

    [Fact]
    public void CreateNotificationService_Webhook_ReturnsWebhookService()
    {
        var settings = new NotificationSettings { Channel = NotificationChannel.Webhook, WebhookUrl = "http://localhost" };
        var service = settings.CreateNotificationService();

        Assert.IsType<WebhookNotificationService>(service);
    }

    [Fact]
    public void CreateNotificationService_Desktop_ReturnsNotifySendService()
    {
        var settings = new NotificationSettings { Channel = NotificationChannel.Desktop };
        var service = settings.CreateNotificationService();

        Assert.IsType<NotifySendNotificationService>(service);
    }
}
