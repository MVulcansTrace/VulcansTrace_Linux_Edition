using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Query;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class InMemoryBaselineStoreTests
{
    [Fact]
    public void Save_And_GetAll_ReturnsEntry()
    {
        var store = new InMemoryBaselineStore();
        var entry = CreateEntry("base-001", AgentIntent.FullAudit, "Production");

        store.Save(entry);
        var all = store.GetAll();

        Assert.Single(all);
        Assert.Equal("base-001", all[0].BaselineId);
    }

    [Fact]
    public void Save_DuplicateId_ReplacesEntry()
    {
        var store = new InMemoryBaselineStore();
        var entry1 = CreateEntry("base-001", AgentIntent.FullAudit, "OldName");
        var entry2 = CreateEntry("base-001", AgentIntent.FullAudit, "NewName");

        store.Save(entry1);
        store.Save(entry2);
        var all = store.GetAll();

        Assert.Single(all);
        Assert.Equal("NewName", all[0].Name);
    }

    [Fact]
    public void GetActive_NoEntries_ReturnsNull()
    {
        var store = new InMemoryBaselineStore();
        var active = store.GetActive(AgentIntent.FullAudit);

        Assert.Null(active);
    }

    [Fact]
    public void SetActive_MarksEntryActive()
    {
        var store = new InMemoryBaselineStore();
        var entry = CreateEntry("base-001", AgentIntent.FullAudit, "Production");
        store.Save(entry);

        store.SetActive("base-001");
        var active = store.GetActive(AgentIntent.FullAudit);

        Assert.NotNull(active);
        Assert.True(active.IsActive);
    }

    [Fact]
    public void SetActive_DeactivatesOtherEntriesForSameIntent()
    {
        var store = new InMemoryBaselineStore();
        var entry1 = CreateEntry("base-001", AgentIntent.FullAudit, "Old");
        var entry2 = CreateEntry("base-002", AgentIntent.FullAudit, "New");
        store.Save(entry1);
        store.Save(entry2);
        store.SetActive("base-001");
        store.SetActive("base-002");

        var active = store.GetActive(AgentIntent.FullAudit);
        var all = store.GetAll();

        Assert.NotNull(active);
        Assert.Equal("base-002", active.BaselineId);
        Assert.Equal(2, all.Count);
        Assert.Single(all, e => e.IsActive);
    }

    [Fact]
    public void SetActive_DifferentIntents_DoNotInterfere()
    {
        var store = new InMemoryBaselineStore();
        var fwEntry = CreateEntry("base-fw", AgentIntent.FirewallCheck, "FW Baseline");
        var sshEntry = CreateEntry("base-ssh", AgentIntent.SshCheck, "SSH Baseline");
        store.Save(fwEntry);
        store.Save(sshEntry);
        store.SetActive("base-fw");
        store.SetActive("base-ssh");

        var fwActive = store.GetActive(AgentIntent.FirewallCheck);
        var sshActive = store.GetActive(AgentIntent.SshCheck);

        Assert.NotNull(fwActive);
        Assert.NotNull(sshActive);
        Assert.True(fwActive.IsActive);
        Assert.True(sshActive.IsActive);
    }

    [Fact]
    public void Delete_RemovesEntry()
    {
        var store = new InMemoryBaselineStore();
        var entry = CreateEntry("base-001", AgentIntent.FullAudit, "Production");
        store.Save(entry);

        store.Delete("base-001");
        var all = store.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void PersistenceWarning_IsNullByDefault()
    {
        var store = new InMemoryBaselineStore();
        Assert.Null(store.PersistenceWarning);
    }

    [Fact]
    public void PersistenceWarning_CanBeSet()
    {
        var store = new InMemoryBaselineStore("Test warning");
        Assert.Equal("Test warning", store.PersistenceWarning);
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
