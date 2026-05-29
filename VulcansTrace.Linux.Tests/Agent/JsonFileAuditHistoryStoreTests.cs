using System.IO;
using System.Text.Json;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class JsonFileAuditHistoryStoreTests : IDisposable
{
    private readonly string _tempFile;

    public JsonFileAuditHistoryStoreTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"vt-test-{Guid.NewGuid()}.json");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempFile))
                File.Delete(_tempFile);
        }
        catch
        {
            // Best effort cleanup
        }
    }

    [Fact]
    public void Append_AddsEntry()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var entry = CreateEntry("snap-1");

        store.Append(entry);
        var all = store.GetAll();

        Assert.Single(all);
        Assert.Equal("snap-1", all[0].SnapshotId);
    }

    [Fact]
    public void Append_Prunes_To_MaxEntries()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 3);

        store.Append(CreateEntry("snap-1"));
        store.Append(CreateEntry("snap-2"));
        store.Append(CreateEntry("snap-3"));
        store.Append(CreateEntry("snap-4"));

        var all = store.GetAll();
        Assert.Equal(3, all.Count);
        Assert.Equal("snap-4", all[0].SnapshotId);
        Assert.Equal("snap-3", all[1].SnapshotId);
        Assert.Equal("snap-2", all[2].SnapshotId);
    }

    [Fact]
    public void LoadFromDisk_SurvivesRecreate()
    {
        var store1 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("snap-1"));
        store1.Append(CreateEntry("snap-2"));
        store1.Dispose();

        var store2 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var all = store2.GetAll();

        Assert.Equal(2, all.Count);
        Assert.Equal("snap-2", all[0].SnapshotId);
        Assert.Equal("snap-1", all[1].SnapshotId);
    }

    [Fact]
    public void LoadFromDisk_NormalizesOrderAndPrunesToMaxEntries()
    {
        var now = DateTime.UtcNow;
        var entries = new[]
        {
            CreateEntry("snap-old", timestampUtc: now.AddMinutes(-20)),
            CreateEntry("snap-new", timestampUtc: now),
            CreateEntry("snap-mid", timestampUtc: now.AddMinutes(-10))
        };
        File.WriteAllText(_tempFile, JsonSerializer.Serialize(entries));

        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 2);
        var all = store.GetAll();

        Assert.Equal(2, all.Count);
        Assert.Equal("snap-new", all[0].SnapshotId);
        Assert.Equal("snap-mid", all[1].SnapshotId);
    }

    [Fact]
    public void Clear_RemovesAllEntries()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store.Append(CreateEntry("snap-1"));
        store.Append(CreateEntry("snap-2"));

        store.Clear();
        var all = store.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void Clear_PersistsEmptyState()
    {
        var store1 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("snap-1"));
        store1.Clear();
        store1.Dispose();

        var store2 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var all = store2.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void Update_ModifiesExistingEntry()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var entry = CreateEntry("snap-1", exported: false);
        store.Append(entry);

        var updated = entry with { Exported = true };
        store.Update(updated);

        var all = store.GetAll();
        Assert.Single(all);
        Assert.True(all[0].Exported);
    }

    [Fact]
    public void Update_PersistsToDisk()
    {
        var store1 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var entry = CreateEntry("snap-1", exported: false);
        store1.Append(entry);
        store1.Update(entry with { Exported = true });
        store1.Dispose();

        var store2 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var all = store2.GetAll();

        Assert.Single(all);
        Assert.True(all[0].Exported);
    }

    [Fact]
    public void Update_NoOp_WhenSnapshotIdNotFound()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store.Append(CreateEntry("snap-1"));

        store.Update(CreateEntry("snap-missing"));

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("snap-1", all[0].SnapshotId);
    }

    [Fact]
    public void BadPath_SetsPersistenceWarning()
    {
        var badPath = Path.Combine("/nonexistent", "dir", "history.json");
        var store = new JsonFileAuditHistoryStore(badPath, maxEntries: 10);
        store.Append(CreateEntry("snap-1"));

        Assert.NotNull(store.PersistenceWarning);
    }

    private static AuditHistoryEntry CreateEntry(string snapshotId, bool exported = false, DateTime? timestampUtc = null)
    {
        return new AuditHistoryEntry
        {
            SnapshotId = snapshotId,
            TimestampUtc = timestampUtc ?? DateTime.UtcNow.AddMinutes(GetSnapshotOrder(snapshotId)),
            Intent = AgentIntent.FullAudit,
            TotalFindings = 1,
            CriticalCount = 0,
            HighCount = 1,
            MediumCount = 0,
            LowCount = 0,
            InfoCount = 0,
            WarningCount = 0,
            PassedCount = 0,
            FailedCount = 1,
            SuppressedCount = 0,
            Exported = exported,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding
                {
                    RuleId = "FW-001",
                    Target = "22/tcp",
                    Severity = "High",
                    ShortDescription = "SSH exposed"
                }
            }
        };
    }

    private static int GetSnapshotOrder(string snapshotId)
    {
        var separatorIndex = snapshotId.LastIndexOf('-');
        if (separatorIndex >= 0 && int.TryParse(snapshotId[(separatorIndex + 1)..], out var order))
        {
            return order;
        }

        return 0;
    }
}
