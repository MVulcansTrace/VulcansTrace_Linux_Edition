using VulcansTrace.Linux.Agent.Rules;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SuppressionStoreTests
{
    [Fact]
    public void InMemoryStore_Add_And_IsSuppressed()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "INPUT", Reason = "Lab box" });

        Assert.True(store.IsSuppressed("FW-001", "INPUT"));
        Assert.False(store.IsSuppressed("FW-001", "OTHER"));
        Assert.False(store.IsSuppressed("FW-002", "INPUT"));
    }

    [Fact]
    public void InMemoryStore_Remove()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "INPUT" });
        store.Remove("FW-001", "INPUT");

        Assert.False(store.IsSuppressed("FW-001", "INPUT"));
    }

    [Fact]
    public void InMemoryStore_GetAll_Returns_Descending_Order()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", CreatedAt = DateTime.UtcNow.AddMinutes(-5) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", CreatedAt = DateTime.UtcNow });

        var all = store.GetAll();
        Assert.Equal(2, all.Count);
        Assert.Equal("FW-002", all[0].RuleId);
        Assert.Equal("FW-001", all[1].RuleId);
    }

    [Fact]
    public void InMemoryStore_Is_Case_Insensitive()
    {
        var store = new InMemorySuppressionStore();
        store.Add(new SuppressionEntry { RuleId = "fw-001", Target = "input" });

        Assert.True(store.IsSuppressed("FW-001", "INPUT"));
    }

    [Fact]
    public void JsonFileStore_Persists_And_Reloads()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store1 = new JsonFileSuppressionStore(path);
            store1.Add(new SuppressionEntry { RuleId = "FW-001", Target = "INPUT", Reason = "Test" });

            var store2 = new JsonFileSuppressionStore(path);
            Assert.True(store2.IsSuppressed("FW-001", "INPUT"));
            Assert.Equal("Test", store2.GetAll()[0].Reason);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void JsonFileStore_Remove_Persists()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store1 = new JsonFileSuppressionStore(path);
            store1.Add(new SuppressionEntry { RuleId = "FW-001", Target = "INPUT" });
            store1.Remove("FW-001", "INPUT");

            var store2 = new JsonFileSuppressionStore(path);
            Assert.False(store2.IsSuppressed("FW-001", "INPUT"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void JsonFileStore_Graceful_When_File_Missing()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".json");
        var store = new JsonFileSuppressionStore(path);

        Assert.Empty(store.GetAll());
        Assert.False(store.IsSuppressed("X", "Y"));
    }

    [Fact]
    public void JsonFileStore_SaveFailure_Surfaces_PersistenceWarning()
    {
        var blockingFile = Path.GetTempFileName();
        try
        {
            var impossiblePath = Path.Combine(blockingFile, "suppressions.json");
            var store = new JsonFileSuppressionStore(impossiblePath);

            store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "INPUT" });

            Assert.True(store.IsSuppressed("FW-001", "INPUT"));
            Assert.Contains("Could not save suppressions", store.PersistenceWarning);
        }
        finally
        {
            File.Delete(blockingFile);
        }
    }
}
