using System.IO;
using System.Text.Json;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
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
    public void Append_RoundTripsFindingSourceHost()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store.Append(CreateEntry("snap-host", sourceHost: "web-prod-01"));
        store.Dispose();

        var reloaded = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var finding = Assert.Single(Assert.Single(reloaded.GetAll()).SnapshotFindings);
        Assert.Equal("web-prod-01", finding.SourceHost);
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
    public void Append_PersistsAttackChainsAcrossRecreate()
    {
        // Attack chains must survive JSON serialization to disk and back so the ShowEvidence
        // attack-chain-membership section works after a process restart.
        var chain = new AttackChain
        {
            RuleIds = new[] { "FW-002", "SSH-002" },
            Links = new[]
            {
                new AttackChainLink { RuleId = "FW-002", Stage = AttackChainStage.InitialAccess, StageName = "Initial Access", Severity = Severity.High },
                new AttackChainLink { RuleId = "SSH-002", Stage = AttackChainStage.Execution, StageName = "Execution", Severity = Severity.High }
            }
        };

        var store1 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        store1.Append(CreateEntry("snap-1") with { AttackChains = new[] { chain } });
        store1.Dispose();

        var store2 = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10);
        var entry = Assert.Single(store2.GetAll());

        var restored = Assert.Single(entry.AttackChains);
        Assert.Equal(new[] { "FW-002", "SSH-002" }, restored.RuleIds);
        Assert.Equal(2, restored.Links.Count);
        Assert.Equal("SSH-002", restored.Links[1].RuleId);
        Assert.Equal(Severity.High, restored.Links[1].Severity);
        Assert.Equal(AttackChainStage.Execution, restored.Links[1].Stage);
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
    public void Append_KeepsNewestEntriesFull_AndSlimsOlderEntries()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 10, fullDetailCount: 3);
        var chain = new AttackChain
        {
            RuleIds = new[] { "FW-002", "SSH-002" },
            Links = new[]
            {
                new AttackChainLink { RuleId = "FW-002", Stage = AttackChainStage.InitialAccess, StageName = "Initial Access", Severity = Severity.High },
                new AttackChainLink { RuleId = "SSH-002", Stage = AttackChainStage.Execution, StageName = "Execution", Severity = Severity.High }
            }
        };
        var caps = new[] { new DataSourceCapability { SourceName = "iptables", Command = "iptables -L -n -v", Status = CapabilityStatus.Available } };

        for (var i = 1; i <= 6; i++)
        {
            store.Append(CreateEntry($"snap-{i}") with
            {
                AttackChains = new[] { chain },
                DataSourceCapabilities = caps,
                RuleResults = new[] { RuleResult.Fail("TEST-001", "Test", "TEST-001", "desc", Severity.High, "target") },
                Warnings = new[] { "warn" },
                LogAnalysisResult = new AnalysisResult()
            });
        }

        var all = store.GetAll();
        Assert.Equal(6, all.Count);

        // Newest 3 entries are full.
        Assert.False(all[0].IsSlimSummary);
        Assert.False(all[1].IsSlimSummary);
        Assert.False(all[2].IsSlimSummary);
        Assert.Single(all[0].AttackChains);
        Assert.Single(all[0].DataSourceCapabilities);
        Assert.Single(all[0].RuleResults);
        Assert.Single(all[0].Warnings);
        Assert.NotNull(all[0].LogAnalysisResult);

        // Older entries are slim.
        Assert.True(all[3].IsSlimSummary);
        Assert.True(all[4].IsSlimSummary);
        Assert.True(all[5].IsSlimSummary);
        Assert.Empty(all[3].AttackChains);
        Assert.Empty(all[3].DataSourceCapabilities);
        Assert.Empty(all[3].RuleResults);
        Assert.Empty(all[3].Warnings);
        Assert.Null(all[3].LogAnalysisResult);
    }

    [Fact]
    public void ToSlimSummary_PreservesSnapshotFindingsAndScorecard_DropsVerboseFields()
    {
        var scorecard = new VulcansTrace.Linux.Core.Compliance.ComplianceScorecard { OverallScore = 42 };
        var entry = CreateEntry("snap-1") with
        {
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding { RuleId = "FW-001", Target = "22/tcp", Severity = "High", ShortDescription = "SSH exposed" }
            },
            Scorecard = scorecard,
            AttackChains = new[] { new AttackChain { RuleIds = new[] { "FW-002" } } },
            DataSourceCapabilities = new[] { new DataSourceCapability { SourceName = "iptables" } },
            RuleResults = new[] { RuleResult.Fail("TEST-001", "Test", "TEST-001", "desc", Severity.High, "target") },
            Warnings = new[] { "warn" },
            LogAnalysisResult = new AnalysisResult()
        };

        var slim = entry.ToSlimSummary();

        Assert.True(slim.IsSlimSummary);
        Assert.Single(slim.SnapshotFindings);
        Assert.Equal("FW-001", slim.SnapshotFindings[0].RuleId);
        Assert.NotNull(slim.Scorecard);
        Assert.Equal(42, slim.Scorecard.OverallScore);
        Assert.Empty(slim.AttackChains);
        Assert.Empty(slim.DataSourceCapabilities);
        Assert.Empty(slim.RuleResults);
        Assert.Empty(slim.Warnings);
        Assert.Null(slim.LogAnalysisResult);
    }

    [Fact]
    public void Append_LatestEntry_RemainsFull_AfterManyAppends()
    {
        var store = new JsonFileAuditHistoryStore(_tempFile, maxEntries: 50, fullDetailCount: 5);

        for (var i = 1; i <= 20; i++)
        {
            store.Append(CreateEntry($"snap-{i}") with
            {
                AttackChains = new[] { new AttackChain { RuleIds = new[] { "FW-002" } } }
            });
        }

        var all = store.GetAll();
        Assert.Equal("snap-20", all[0].SnapshotId);
        Assert.False(all[0].IsSlimSummary);
        Assert.Single(all[0].AttackChains);
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

    private static AuditHistoryEntry CreateEntry(string snapshotId, bool exported = false, DateTime? timestampUtc = null, string? sourceHost = null)
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
                    ShortDescription = "SSH exposed",
                    SourceHost = sourceHost ?? string.Empty
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
