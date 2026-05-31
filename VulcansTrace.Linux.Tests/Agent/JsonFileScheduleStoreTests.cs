using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class JsonFileScheduleStoreTests : IDisposable
{
    private readonly string _tempFile;

    public JsonFileScheduleStoreTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"vt-test-schedules-{Guid.NewGuid()}.json");
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
        var store = new JsonFileScheduleStore(_tempFile);
        var schedule = CreateSchedule("sched-001", AgentIntent.FullAudit, "Daily Audit", "0 6 * * *");
        store.Save(schedule);

        var store2 = new JsonFileScheduleStore(_tempFile);
        var all = store2.GetAll();

        Assert.Single(all);
        Assert.Equal("sched-001", all[0].Id);
        Assert.Equal("Daily Audit", all[0].Name);
    }

    [Fact]
    public void Save_DuplicateId_ReplacesEntry()
    {
        var store = new JsonFileScheduleStore(_tempFile);
        store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "OldName", "0 6 * * *"));
        store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "NewName", "0 7 * * *"));

        var all = store.GetAll();
        Assert.Single(all);
        Assert.Equal("NewName", all[0].Name);
        Assert.Equal("0 7 * * *", all[0].CronExpression);
    }

    [Fact]
    public void GetById_ReturnsCorrectEntry()
    {
        var store = new JsonFileScheduleStore(_tempFile);
        store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "Daily", "0 6 * * *"));
        store.Save(CreateSchedule("sched-002", AgentIntent.FirewallCheck, "Weekly", "0 6 * * 1"));

        var found = store.GetById("sched-002");
        Assert.NotNull(found);
        Assert.Equal(AgentIntent.FirewallCheck, found.Intent);

        var missing = store.GetById("sched-999");
        Assert.Null(missing);
    }

    [Fact]
    public void Delete_PersistsToDisk()
    {
        var store = new JsonFileScheduleStore(_tempFile);
        store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "Daily", "0 6 * * *"));
        store.Delete("sched-001");

        var store2 = new JsonFileScheduleStore(_tempFile);
        var all = store2.GetAll();

        Assert.Empty(all);
    }

    [Fact]
    public void PersistenceWarning_Null_WhenHealthy()
    {
        var store = new JsonFileScheduleStore(_tempFile);
        store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "Daily", "0 6 * * *"));
        Assert.Null(store.PersistenceWarning);
    }

    [Fact]
    public void PersistenceWarning_Set_WhenFileCorrupt()
    {
        File.WriteAllText(_tempFile, "not valid json");
        var store = new JsonFileScheduleStore(_tempFile);
        Assert.NotNull(store.PersistenceWarning);
    }

    [Fact]
    public void CreateDefault_CreatesDirectoryAndFile()
    {
        var customConfigDir = Path.Combine(Path.GetTempPath(), $"vt-test-config-{Guid.NewGuid()}");
        Environment.SetEnvironmentVariable("XDG_CONFIG_HOME", customConfigDir);
        try
        {
            var store = JsonFileScheduleStore.CreateDefault();
            store.Save(CreateSchedule("sched-001", AgentIntent.FullAudit, "Daily", "0 6 * * *"));

            Assert.True(Directory.Exists(Path.Combine(customConfigDir, "VulcansTrace")));
            Assert.True(File.Exists(Path.Combine(customConfigDir, "VulcansTrace", "schedules.json")));
        }
        finally
        {
            Environment.SetEnvironmentVariable("XDG_CONFIG_HOME", null);
            try
            {
                if (Directory.Exists(customConfigDir))
                    Directory.Delete(customConfigDir, recursive: true);
            }
            catch { }
        }
    }

    private static AuditSchedule CreateSchedule(string id, AgentIntent intent, string name, string cron)
    {
        return new AuditSchedule
        {
            Id = id,
            Name = name,
            Intent = intent,
            CronExpression = cron
        };
    }
}
