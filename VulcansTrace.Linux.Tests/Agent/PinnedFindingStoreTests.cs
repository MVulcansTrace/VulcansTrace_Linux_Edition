using System.Text.Json;
using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Core.Logging;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class PinnedFindingStoreTests
{
    [Fact]
    public void InMemoryPinnedFindingStore_PinAndUnpin()
    {
        var store = new InMemoryPinnedFindingStore();
        var finding = CreatePinnedFinding("fp-1");

        Assert.False(store.IsPinned("fp-1"));

        store.Pin(finding);

        Assert.True(store.IsPinned("fp-1"));
        Assert.Single(store.GetAll());

        store.Unpin("fp-1");

        Assert.False(store.IsPinned("fp-1"));
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public void InMemoryPinnedFindingStore_PinReplacesExisting()
    {
        var store = new InMemoryPinnedFindingStore();
        var original = CreatePinnedFinding("fp-1", shortDescription: "Original");
        var updated = CreatePinnedFinding("fp-1", shortDescription: "Updated");

        store.Pin(original);
        store.Pin(updated);

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("Updated", all[0].ShortDescription);
    }

    [Fact]
    public void InMemoryPinnedFindingStore_GetAll_OrdersByPinnedAtDescending()
    {
        var store = new InMemoryPinnedFindingStore();
        var first = CreatePinnedFinding("fp-1", pinnedAtUtc: DateTime.UtcNow.AddMinutes(-5));
        var second = CreatePinnedFinding("fp-2", pinnedAtUtc: DateTime.UtcNow);
        var third = CreatePinnedFinding("fp-3", pinnedAtUtc: DateTime.UtcNow.AddMinutes(-10));

        store.Pin(first);
        store.Pin(second);
        store.Pin(third);

        var all = store.GetAll();
        Assert.Equal("fp-2", all[0].Fingerprint);
        Assert.Equal("fp-1", all[1].Fingerprint);
        Assert.Equal("fp-3", all[2].Fingerprint);
    }

    [Fact]
    public void JsonFilePinnedFindingStore_RoundTrip()
    {
        var path = GetTempFilePath();
        try
        {
            var store = new JsonFilePinnedFindingStore(path);
            var finding = CreatePinnedFinding("fp-roundtrip", notes: "remember this");

            store.Pin(finding);

            var reloaded = new JsonFilePinnedFindingStore(path);

            Assert.True(reloaded.IsPinned("fp-roundtrip"));
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
    public void JsonFilePinnedFindingStore_InvalidPath_FallsBackToInMemoryBehaviorWithWarning()
    {
        var path = Path.Combine("/nonexistent-directory-xyz", "pinned-findings.json");
        var store = new JsonFilePinnedFindingStore(path);

        store.Pin(CreatePinnedFinding("fp-1"));

        Assert.True(store.IsPinned("fp-1"));
        Assert.NotNull(store.PersistenceWarning);
    }

    [Fact]
    public void JsonFilePinnedFindingStore_CorruptFile_QuarantinesAndContinues()
    {
        var path = GetTempFilePath();
        File.WriteAllText(path, "{ not valid json");

        try
        {
            var store = new JsonFilePinnedFindingStore(path);

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
    public void JsonFilePinnedFindingStore_InvalidEntry_LoadsValidAndWarns()
    {
        var path = GetTempFilePath();
        var json = JsonSerializer.Serialize(new[]
        {
            new { Fingerprint = "fp-valid", Category = "PortScan", Severity = "High", SourceHost = "1.1.1.1", Target = "2.2.2.2", ShortDescription = "ok", PinnedAtUtc = DateTime.UtcNow },
            new { Fingerprint = "", Category = "", Severity = "", SourceHost = "", Target = "", ShortDescription = "", PinnedAtUtc = DateTime.UtcNow }
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        File.WriteAllText(path, json);

        try
        {
            var store = new JsonFilePinnedFindingStore(path);

            Assert.True(store.IsPinned("fp-valid"));
            Assert.Single(store.GetAll());
            Assert.NotNull(store.PersistenceWarning);
        }
        finally
        {
            CleanUp(path);
        }
    }

    [Fact]
    public void JsonFilePinnedFindingStore_Dispose_DoesNotThrow()
    {
        var store = new JsonFilePinnedFindingStore(GetTempFilePath());
        store.Dispose();
    }

    private static PinnedFinding CreatePinnedFinding(
        string fingerprint,
        string shortDescription = "Test finding",
        string notes = "",
        DateTime? pinnedAtUtc = null)
    {
        return new PinnedFinding
        {
            Fingerprint = fingerprint,
            RuleId = "FW-001",
            Category = "PortScan",
            Severity = "High",
            SourceHost = "192.168.1.1",
            Target = "10.0.0.1",
            ShortDescription = shortDescription,
            Notes = notes,
            PinnedAtUtc = pinnedAtUtc ?? DateTime.UtcNow
        };
    }

    private static string GetTempFilePath()
    {
        var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "pinned-findings.json");
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
