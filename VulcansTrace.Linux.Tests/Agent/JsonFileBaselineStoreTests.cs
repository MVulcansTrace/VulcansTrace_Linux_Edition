using System.Text.Json;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Query;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class JsonFileBaselineStoreTests : IDisposable
{
    private readonly string _tempFile;

    public JsonFileBaselineStoreTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"vt-test-baselines-{Guid.NewGuid()}.json");
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
    public void Save_And_Reload_ReturnsEntry()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        var entry = CreateEntry("base-001", AgentIntent.FullAudit, "Production");
        store.Save(entry);

        var store2 = new JsonFileBaselineStore(_tempFile);
        var all = store2.GetAll();

        Assert.Single(all);
        Assert.Equal("base-001", all[0].BaselineId);
    }

    [Fact]
    public void Save_DuplicateId_ReplacesEntry()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "OldName"));
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "NewName"));

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("NewName", all[0].Name);
    }

    [Fact]
    public void SetActive_PersistsToDisk()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "Production"));
        store.SetActive("base-001");

        var store2 = new JsonFileBaselineStore(_tempFile);
        var active = store2.GetActive(AgentIntent.FullAudit);

        Assert.NotNull(active);
        Assert.True(active.IsActive);
    }

    [Fact]
    public void Delete_PersistsToDisk()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "Production"));
        store.Delete("base-001");

        var store2 = new JsonFileBaselineStore(_tempFile);
        var all = store2.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void PersistenceWarning_Null_WhenHealthy()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "Production"));
        Assert.Null(store.PersistenceWarning);
    }

    [Fact]
    public void PersistenceWarning_Set_WhenFileCorrupt()
    {
        File.WriteAllText(_tempFile, "not valid json");
        var store = new JsonFileBaselineStore(_tempFile);
        Assert.NotNull(store.PersistenceWarning);
    }

    [Fact]
    public void CreateDefault_CreatesDirectoryAndFile()
    {
        var customConfigDir = Path.Combine(Path.GetTempPath(), $"vt-test-config-{Guid.NewGuid()}");
        try
        {
            var store = JsonFileBaselineStore.CreateDefault(customConfigDir);
            store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "Production"));

            Assert.True(Directory.Exists(Path.Combine(customConfigDir, "VulcansTrace")));
            Assert.True(File.Exists(Path.Combine(customConfigDir, "VulcansTrace", "baselines.json")));
        }
        finally
        {
            try
            {
                if (Directory.Exists(customConfigDir))
                    Directory.Delete(customConfigDir, recursive: true);
            }
            catch { }
        }
    }

    [Fact]
    public void SetActive_DeactivatesOtherEntriesForSameIntent()
    {
        var store = new JsonFileBaselineStore(_tempFile);
        store.Save(CreateEntry("base-001", AgentIntent.FullAudit, "Old"));
        store.Save(CreateEntry("base-002", AgentIntent.FullAudit, "New"));
        store.SetActive("base-001");
        store.SetActive("base-002");

        var active = store.GetActive(AgentIntent.FullAudit);
        var all = store.GetAll();

        Assert.NotNull(active);
        Assert.Equal("base-002", active.BaselineId);
        Assert.Single(all, e => e.IsActive);
    }

    private static BaselineEntry CreateEntry(string id, AgentIntent intent, string name)
    {
        return new BaselineEntry
        {
            BaselineId = id,
            Name = name,
            Intent = intent,
            SnapshotFindings = Array.Empty<VulcansTrace.Linux.Agent.Reports.AuditSnapshotFinding>()
        };
    }
}
