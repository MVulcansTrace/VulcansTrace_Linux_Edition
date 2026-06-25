using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class JsonFileStoreTransactionalValidationTests : IDisposable
{
    private readonly string _tempDir;

    public JsonFileStoreTransactionalValidationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best effort cleanup.
        }
    }

    [Fact]
    public void ThreatIntelImport_InvalidEntry_DoesNotMutateMemoryOrBlockLaterValidImport()
    {
        var filePath = Path.Combine(_tempDir, "threat-intel.json");
        using var store = new JsonFileThreatIntelStore(filePath);

        store.Import(new[]
        {
            new IocEntry { Type = IocType.FileHash, Value = "not-hex!", Source = "test" }
        });

        Assert.Equal(0, store.Count);
        Assert.NotNull(store.PersistenceWarning);

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", Source = "test" }
        });

        Assert.Null(store.PersistenceWarning);
        Assert.Equal(1, store.Count);
        Assert.Equal("1.2.3.4", store.GetByType(IocType.IPv4)[0].Value);

        using var reloaded = new JsonFileThreatIntelStore(filePath);
        Assert.Equal(1, reloaded.Count);
        Assert.Equal("1.2.3.4", reloaded.GetByType(IocType.IPv4)[0].Value);
    }

    [Fact]
    public void ScheduleSave_InvalidSchedule_DoesNotMutateMemoryOrBlockLaterValidSave()
    {
        var filePath = Path.Combine(_tempDir, "schedules.json");
        using var store = new JsonFileScheduleStore(filePath);
        var valid = new AuditSchedule
        {
            Id = "sched-1",
            Name = "Weekly",
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 6 * * 1"
        };
        store.Save(valid);

        store.Save(valid with { Id = "sched-bad", CronExpression = "not-a-cron" });

        Assert.NotNull(store.PersistenceWarning);
        Assert.Single(store.GetAll());
        Assert.Null(store.GetById("sched-bad"));

        store.Save(valid with { Id = "sched-2", Name = "Daily", CronExpression = "0 7 * * *" });

        Assert.Null(store.PersistenceWarning);
        Assert.Equal(2, store.GetAll().Count);

        using var reloaded = new JsonFileScheduleStore(filePath);
        Assert.Equal(2, reloaded.GetAll().Count);
        Assert.Null(reloaded.GetById("sched-bad"));
    }
}
