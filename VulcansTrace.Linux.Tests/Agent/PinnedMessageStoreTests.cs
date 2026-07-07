using System.Text.Json;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Core.Logging;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class PinnedMessageStoreTests
{
    [Fact]
    public void InMemoryPinnedMessageStore_PinAndUnpin()
    {
        var store = new InMemoryPinnedMessageStore();
        var message = CreatePinnedMessage();

        Assert.False(store.IsPinned(message.MessageId));

        store.Pin(message);

        Assert.True(store.IsPinned(message.MessageId));
        Assert.Single(store.GetAll());

        store.Unpin(message.MessageId);

        Assert.False(store.IsPinned(message.MessageId));
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public void InMemoryPinnedMessageStore_PinReplacesExisting()
    {
        var store = new InMemoryPinnedMessageStore();
        var messageId = Guid.NewGuid().ToString("N");
        var original = CreatePinnedMessage(messageId, text: "Original");
        var updated = CreatePinnedMessage(messageId, text: "Updated");

        store.Pin(original);
        store.Pin(updated);

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("Updated", all[0].Text);
    }

    [Fact]
    public void InMemoryPinnedMessageStore_GetAll_OrdersByPinnedAtDescending()
    {
        var store = new InMemoryPinnedMessageStore();
        var first = CreatePinnedMessage(pinnedAtUtc: DateTime.UtcNow.AddMinutes(-5));
        var second = CreatePinnedMessage(pinnedAtUtc: DateTime.UtcNow);
        var third = CreatePinnedMessage(pinnedAtUtc: DateTime.UtcNow.AddMinutes(-10));

        store.Pin(first);
        store.Pin(second);
        store.Pin(third);

        var all = store.GetAll();
        Assert.Equal(second.MessageId, all[0].MessageId);
        Assert.Equal(first.MessageId, all[1].MessageId);
        Assert.Equal(third.MessageId, all[2].MessageId);
    }

    [Fact]
    public void JsonFilePinnedMessageStore_RoundTrip()
    {
        var path = GetTempFilePath();
        try
        {
            var store = new JsonFilePinnedMessageStore(path);
            var message = CreatePinnedMessage(notes: "remember this");
            var messageId = message.MessageId;

            store.Pin(message);

            var reloaded = new JsonFilePinnedMessageStore(path);

            Assert.True(reloaded.IsPinned(messageId));
            var all = reloaded.GetAll();
            Assert.Single(all);
            Assert.Equal("remember this", all[0].Notes);
            Assert.Null(reloaded.PersistenceWarning);
        }
        finally
        {
            CleanUp(path);
        }
    }

    [Fact]
    public void JsonFilePinnedMessageStore_InvalidPath_FallsBackToInMemoryBehaviorWithWarning()
    {
        var path = Path.Combine("/nonexistent-directory-xyz", "pinned-messages.json");
        var store = new JsonFilePinnedMessageStore(path);
        var message = CreatePinnedMessage();

        store.Pin(message);

        Assert.True(store.IsPinned(message.MessageId));
        Assert.NotNull(store.PersistenceWarning);
    }

    [Fact]
    public void JsonFilePinnedMessageStore_CorruptFile_QuarantinesAndContinues()
    {
        var path = GetTempFilePath();
        File.WriteAllText(path, "{ not valid json");

        try
        {
            var store = new JsonFilePinnedMessageStore(path);

            Assert.False(store.IsPinned("anything"));
            Assert.NotNull(store.PersistenceWarning);
            Assert.Contains("quarantined", store.PersistenceWarning, StringComparison.OrdinalIgnoreCase);
            Assert.True(Directory.GetFiles(Path.GetDirectoryName(path)!, "*.corrupt.*").Length > 0);
        }
        finally
        {
            CleanUp(path);
        }
    }

    [Fact]
    public void JsonFilePinnedMessageStore_InvalidEntry_LoadsValidAndWarns()
    {
        var path = GetTempFilePath();
        var validMessageId = Guid.NewGuid().ToString("N");
        var json = JsonSerializer.Serialize(new[]
        {
            new { MessageId = validMessageId, IsUser = false, Text = "ok", Details = "", Category = "", Severity = "", IsInfo = true, IsError = false, IsProse = true, TimestampUtc = DateTime.UtcNow, PinnedAtUtc = DateTime.UtcNow },
            new { MessageId = "", IsUser = false, Text = "", Details = "", Category = "", Severity = "", IsInfo = false, IsError = false, IsProse = false, TimestampUtc = DateTime.UtcNow, PinnedAtUtc = DateTime.UtcNow }
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        File.WriteAllText(path, json);

        try
        {
            var store = new JsonFilePinnedMessageStore(path);

            Assert.True(store.IsPinned(validMessageId));
            Assert.Single(store.GetAll());
            Assert.NotNull(store.PersistenceWarning);
        }
        finally
        {
            CleanUp(path);
        }
    }

    [Fact]
    public void JsonFilePinnedMessageStore_Dispose_DoesNotThrow()
    {
        var store = new JsonFilePinnedMessageStore(GetTempFilePath());
        store.Dispose();
    }

    private static PinnedMessage CreatePinnedMessage(
        string? messageId = null,
        string text = "Test message",
        string notes = "",
        DateTime? pinnedAtUtc = null)
    {
        return new PinnedMessage
        {
            MessageId = messageId ?? Guid.NewGuid().ToString("N"),
            IsUser = false,
            Text = text,
            Details = "details",
            Category = "Firewall",
            Severity = "High",
            IsInfo = true,
            IsError = false,
            IsProse = true,
            TimestampUtc = DateTime.UtcNow,
            PinnedAtUtc = pinnedAtUtc ?? DateTime.UtcNow,
            Notes = notes
        };
    }

    private static string GetTempFilePath()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "pinned-messages.json");
    }

    private static void CleanUp(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (dir != null && Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}
