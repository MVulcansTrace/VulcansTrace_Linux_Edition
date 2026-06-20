using System.Text.Json;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;
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

    [Fact]
    public async Task SaveAndLoad_RoundTripsRuleHistory()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        var snapshot = new AgentMemorySnapshot
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["FW-001"] = new RuleMemoryEntry
                {
                    RuleId = "FW-001",
                    Category = "Firewall",
                    FirstSeenUtc = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                    LastSeenUtc = new DateTime(2026, 6, 18, 0, 0, 0, DateTimeKind.Utc),
                    LastSeverity = Severity.High,
                    Trend = RuleStatusTrend.Stable,
                    SeverityHistory = new[]
                    {
                        new RuleSeveritySnapshot
                        {
                            UtcTimestamp = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                            Severity = Severity.High,
                            Target = "0.0.0.0/0"
                        },
                        new RuleSeveritySnapshot
                        {
                            UtcTimestamp = new DateTime(2026, 6, 18, 0, 0, 0, DateTimeKind.Utc),
                            Severity = Severity.High,
                            Target = "0.0.0.0/0"
                        }
                    }
                }
            }
        };

        await store.SaveAsync(snapshot);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Single(loaded.RuleHistory);
        var entry = loaded.RuleHistory["FW-001"];
        Assert.Equal("Firewall", entry.Category);
        Assert.Equal(RuleStatusTrend.Stable, entry.Trend);
        Assert.Equal(2, entry.SeverityHistory.Count);
        Assert.Equal(Severity.High, entry.LastSeverity);
    }

    [Fact]
    public async Task SaveAndLoad_RoundTripsCheckedCategories()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        var snapshot = new AgentMemorySnapshot
        {
            CheckedCategories = new[]
            {
                new CategoryAuditEntry { Category = "SSH", UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc) },
                new CategoryAuditEntry { Category = "Firewall", UtcTimestamp = new DateTime(2026, 6, 20, 11, 0, 0, DateTimeKind.Utc) }
            }
        };

        await store.SaveAsync(snapshot);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Equal(2, loaded.CheckedCategories.Count);
        Assert.Contains(loaded.CheckedCategories, e => e.Category == "SSH" && e.UtcTimestamp == new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc));
        Assert.Contains(loaded.CheckedCategories, e => e.Category == "Firewall" && e.UtcTimestamp == new DateTime(2026, 6, 20, 11, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public async Task SaveAndLoad_PreservesCheckedCategoriesOrderAndDuplicates()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        var snapshot = new AgentMemorySnapshot
        {
            CheckedCategories = new[]
            {
                new CategoryAuditEntry { Category = "SSH", UtcTimestamp = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc) },
                new CategoryAuditEntry { Category = "Firewall", UtcTimestamp = new DateTime(2026, 6, 20, 11, 0, 0, DateTimeKind.Utc) },
                new CategoryAuditEntry { Category = "ssh", UtcTimestamp = new DateTime(2026, 6, 20, 10, 0, 0, DateTimeKind.Utc) }
            }
        };

        await store.SaveAsync(snapshot);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Equal(3, loaded.CheckedCategories.Count);
        Assert.Equal("SSH", loaded.CheckedCategories[0].Category);
        Assert.Equal("Firewall", loaded.CheckedCategories[1].Category);
        Assert.Equal("ssh", loaded.CheckedCategories[2].Category);
    }

    [Fact]
    public void Load_PascalCaseKeys_BindsCaseInsensitively()
    {
        // The store writes camelCase but must also read PascalCase (hand-edited / external files)
        // so legacy or externally-authored snapshots don't silently drop fields.
        File.WriteAllText(_filePath,
            "{\"CheckedCategories\":[{\"Category\":\"SSH\",\"UtcTimestamp\":\"2026-06-20T12:00:00Z\"}]," +
            "\"LastIntent\":\"FullAudit\"}");

        var store = new JsonFileAgentMemoryStore(_filePath);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Single(loaded.CheckedCategories);
        Assert.Equal("SSH", loaded.CheckedCategories[0].Category);
        Assert.Equal(AgentIntent.FullAudit, loaded.LastIntent);
    }

    [Fact]
    public void Load_LegacySnapshotWithoutCheckedCategories_DeserializesToEmptyList()
    {
        File.WriteAllText(_filePath, "{\"lastIntent\": \"FullAudit\", \"lastTopic\": \"Audit\"}");

        var store = new JsonFileAgentMemoryStore(_filePath);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.NotNull(loaded.CheckedCategories);
        Assert.Empty(loaded.CheckedCategories);
    }

    [Fact]
    public void Load_MissingRuleHistory_ReturnsEmptyDictionary()
    {
        File.WriteAllText(_filePath, "{\"lastIntent\": \"FullAudit\", \"lastTopic\": \"Audit\"}");

        var store = new JsonFileAgentMemoryStore(_filePath);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.NotNull(loaded.RuleHistory);
        Assert.Empty(loaded.RuleHistory);
    }

    [Fact]
    public void Load_RestoresCaseInsensitiveRuleHistory()
    {
        File.WriteAllText(_filePath, "{\"ruleHistory\": {\"fw-001\": {\"ruleId\": \"fw-001\", \"category\": \"Firewall\", \"lastSeverity\": \"High\", \"trend\": \"Stable\"}}}");

        var store = new JsonFileAgentMemoryStore(_filePath);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        Assert.Single(loaded.RuleHistory);
        Assert.True(loaded.RuleHistory.ContainsKey("FW-001"));
        Assert.Equal("FW-001", loaded.RuleHistory["FW-001"].RuleId);
    }

    [Fact]
    public void Load_LegacySnapshotWithoutCycles_DeserializesToEmptyCycles()
    {
        File.WriteAllText(_filePath, "{\"ruleHistory\": {\"fw-001\": {\"ruleId\": \"fw-001\", \"category\": \"Firewall\", \"lastSeverity\": \"High\", \"trend\": \"Stable\", \"lastVerifiedFixedUtc\": \"2026-06-10T00:00:00Z\"}}}");

        var store = new JsonFileAgentMemoryStore(_filePath);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        var entry = loaded.RuleHistory["FW-001"];
        Assert.NotNull(entry.RemediationCycles);
        Assert.Empty(entry.RemediationCycles);
        Assert.Equal(new DateTime(2026, 6, 10, 0, 0, 0, DateTimeKind.Utc), entry.LastVerifiedFixedUtc);
    }

    [Fact]
    public async Task SaveAndLoad_RoundTripsRemediationCycles()
    {
        var store = new JsonFileAgentMemoryStore(_filePath);
        var snapshot = new AgentMemorySnapshot
        {
            RuleHistory = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["SSH-002"] = new RuleMemoryEntry
                {
                    RuleId = "SSH-002",
                    Category = "SSH",
                    RemediationCycles = new[]
                    {
                        new RemediationCycle
                        {
                            AttemptedUtc = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                            VerifiedFixedUtc = new DateTime(2026, 6, 2, 0, 0, 0, DateTimeKind.Utc),
                            ReturnedUtc = new DateTime(2026, 6, 5, 0, 0, 0, DateTimeKind.Utc),
                            CycleNumber = 1
                        },
                        new RemediationCycle
                        {
                            AttemptedUtc = new DateTime(2026, 6, 6, 0, 0, 0, DateTimeKind.Utc),
                            VerifiedFixedUtc = new DateTime(2026, 6, 7, 0, 0, 0, DateTimeKind.Utc),
                            CycleNumber = 2
                        }
                    }
                }
            }
        };

        await store.SaveAsync(snapshot);
        var loaded = store.Load();

        Assert.NotNull(loaded);
        var entry = loaded.RuleHistory["SSH-002"];
        Assert.Equal(2, entry.RemediationCycles.Count);
        Assert.True(entry.RemediationCycles[0].IsClosed);
        Assert.False(entry.RemediationCycles[1].IsClosed);
    }
}
