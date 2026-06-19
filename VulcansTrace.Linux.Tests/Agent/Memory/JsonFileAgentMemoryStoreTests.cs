using System.Text.Json;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Memory;

public class JsonFileAgentMemoryStoreTests : IDisposable
{
    private readonly string _filePath = Path.Combine(Path.GetTempPath(), $"vulcanstrace-memory-{Guid.NewGuid()}.json");

    public void Dispose()
    {
        try { File.Delete(_filePath); } catch { }
    }

    [Fact]
    public void Load_WhenFileMissing_ReturnsNull()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);

        Assert.Null(store.Load());
        Assert.Null(store.PersistenceWarning);
    }

    [Fact]
    public async Task SaveAndLoad_RoundTripsSnapshot()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        var snapshot = new AgentMemorySnapshot
        {
            UtcTimestamp = new DateTime(2026, 6, 18, 12, 0, 0, DateTimeKind.Utc),
            LastIntent = AgentIntent.ExplainFinding,
            LastTopic = ConversationTopic.Explanation,
            LastAuditIntent = AgentIntent.FullAudit,
            FocusedRuleId = "FW-001",
            FocusedCategory = "Firewall",
            LastRemediationSessionId = "a1b2c3d4",
            ActiveSessionId = "a1b2c3d4",
            LatestAuditSnapshotId = "snap1234",
            RecentTurns = new[] { DialogueTurn.Now("explain FW-001", AgentIntent.ExplainFinding, "FW-001") }
        };

        await store.SaveAsync(snapshot);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Equal(snapshot.LastIntent, loaded.LastIntent);
        Assert.Equal(snapshot.LastTopic, loaded.LastTopic);
        Assert.Equal(snapshot.LastAuditIntent, loaded.LastAuditIntent);
        Assert.Equal(snapshot.FocusedRuleId, loaded.FocusedRuleId);
        Assert.Equal(snapshot.FocusedCategory, loaded.FocusedCategory);
        Assert.Equal(snapshot.LastRemediationSessionId, loaded.LastRemediationSessionId);
        Assert.Equal(snapshot.ActiveSessionId, loaded.ActiveSessionId);
        Assert.Equal(snapshot.LatestAuditSnapshotId, loaded.LatestAuditSnapshotId);
        Assert.Single(loaded.RecentTurns);
        Assert.Null(store.PersistenceWarning);
    }

    [Fact]
    public void Save_CorruptFile_ReturnsPersistenceWarning()
    {
        File.WriteAllText(_filePath, "not json");
        var store = new JsonFileAgentMemoryStore(_filePath);

        Assert.NotNull(store.PersistenceWarning);
        Assert.Null(store.Load());
    }

    [Fact]
    public async Task Save_OverwritesExistingFile()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        await store.SaveAsync(new AgentMemorySnapshot { LastIntent = AgentIntent.Help });
        await store.SaveAsync(new AgentMemorySnapshot { LastIntent = AgentIntent.FullAudit });

        var loaded = store.Load();
        Assert.Equal(AgentIntent.FullAudit, loaded!.LastIntent);
    }

    [Fact]
    public async Task SavedFile_UsesReadableEnums()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        await store.SaveAsync(new AgentMemorySnapshot { LastIntent = AgentIntent.FullAudit, LastTopic = ConversationTopic.Audit });

        var json = File.ReadAllText(_filePath);
        Assert.Contains("\"lastIntent\": \"FullAudit\"", json);
        Assert.Contains("\"lastTopic\": \"Audit\"", json);
    }
}
