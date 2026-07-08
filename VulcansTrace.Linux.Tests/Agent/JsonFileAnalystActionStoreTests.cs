using System;
using System.IO;
using System.Text.Json;
using VulcansTrace.Linux.Agent.Actions;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class JsonFileAnalystActionStoreTests : IDisposable
{
    private readonly string _tempFile;

    public JsonFileAnalystActionStoreTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"vt-analyst-actions-{Guid.NewGuid()}.json");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempFile))
                File.Delete(_tempFile);
            if (File.Exists(_tempFile + ".lock"))
                File.Delete(_tempFile + ".lock");

            // LoadFromDisk quarantines corrupt files to <name>.corrupt.*.<ext>; clean those too.
            var directory = Path.GetDirectoryName(_tempFile);
            if (!string.IsNullOrEmpty(directory))
            {
                foreach (var quarantined in Directory.GetFiles(directory, Path.GetFileNameWithoutExtension(_tempFile) + ".corrupt.*"))
                    File.Delete(quarantined);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }

    [Fact]
    public void Append_AddsEntry()
    {
        var store = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        var entry = CreateEntry("id-1");

        store.Append(entry);
        var all = store.GetAll();

        Assert.Single(all);
        Assert.Equal("id-1", all[0].Id);
    }

    [Fact]
    public void Append_Prunes_To_MaxEntries()
    {
        var store = new JsonFileAnalystActionStore(_tempFile, maxEntries: 3);

        store.Append(CreateEntry("id-1", minutesAgo: 30));
        store.Append(CreateEntry("id-2", minutesAgo: 20));
        store.Append(CreateEntry("id-3", minutesAgo: 10));
        store.Append(CreateEntry("id-4", minutesAgo: 0));

        var all = store.GetAll();
        Assert.Equal(3, all.Count);
        Assert.Equal("id-4", all[0].Id);
        Assert.Equal("id-3", all[1].Id);
        Assert.Equal("id-2", all[2].Id);
    }

    [Fact]
    public void LoadFromDisk_SurvivesRecreate()
    {
        var store1 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("id-1"));
        store1.Append(CreateEntry("id-2"));
        store1.Dispose();

        var store2 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        var all = store2.GetAll();

        Assert.Equal(2, all.Count);
        Assert.Equal("id-2", all[0].Id);
        Assert.Equal("id-1", all[1].Id);
    }

    [Fact]
    public void Append_MergesEntriesFromOtherStoreInstances()
    {
        using var store1 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("id-1", minutesAgo: 30));

        using (var store2 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10))
        {
            store2.Append(CreateEntry("id-2", minutesAgo: 20));
        }

        store1.Append(CreateEntry("id-3", minutesAgo: 10));

        using var fresh = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        var ids = fresh.GetAll().Select(e => e.Id).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(3, ids.Count);
        Assert.Contains("id-1", ids);
        Assert.Contains("id-2", ids);
        Assert.Contains("id-3", ids);
    }

    [Fact]
    public void LoadFromDisk_NormalizesOrderAndPrunesToMaxEntries()
    {
        var now = DateTime.UtcNow;
        var entries = new[]
        {
            CreateEntry("id-old", timestampUtc: now.AddMinutes(-20)),
            CreateEntry("id-new", timestampUtc: now),
            CreateEntry("id-mid", timestampUtc: now.AddMinutes(-10))
        };
        File.WriteAllText(_tempFile, JsonSerializer.Serialize(entries));

        var store = new JsonFileAnalystActionStore(_tempFile, maxEntries: 2);
        var all = store.GetAll();

        Assert.Equal(2, all.Count);
        Assert.Equal("id-new", all[0].Id);
        Assert.Equal("id-mid", all[1].Id);
    }

    [Fact]
    public void Clear_RemovesAllEntries()
    {
        var store = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        store.Append(CreateEntry("id-1"));
        store.Append(CreateEntry("id-2"));

        store.Clear();
        var all = store.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void Clear_PersistsEmptyState()
    {
        var store1 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("id-1"));
        store1.Clear();
        store1.Dispose();

        var store2 = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);
        var all = store2.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void BadPath_SetsPersistenceWarning()
    {
        var badPath = Path.Combine("/nonexistent", "dir", "actions.json");
        var store = new JsonFileAnalystActionStore(badPath, maxEntries: 10);
        store.Append(CreateEntry("id-1"));

        Assert.NotNull(store.PersistenceWarning);
    }

    [Fact]
    public void LoadFromDisk_CorruptJson_QuarantinesAndEmpties()
    {
        // Simulate a crash mid-write: valid JSON head, truncated (unterminated) second entry.
        File.WriteAllText(_tempFile, "[{\"id\":\"a1\",\"timestampUtc\":\"2026-01-01T00:00:00Z\",\"actor\":\"cli\",\"actionType\":\"AuditRan\"},{");

        using var store = new JsonFileAnalystActionStore(_tempFile, maxEntries: 10);

        Assert.Empty(store.GetAll());
        Assert.NotNull(store.PersistenceWarning);
        Assert.False(File.Exists(_tempFile));
    }

    private static AnalystActionEntry CreateEntry(string id, int minutesAgo = 0, DateTime? timestampUtc = null)
    {
        return new AnalystActionEntry
        {
            Id = id,
            TimestampUtc = timestampUtc ?? DateTime.UtcNow.AddMinutes(-minutesAgo),
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan,
            Target = "FullAudit",
            Details = "findings=1"
        };
    }
}
