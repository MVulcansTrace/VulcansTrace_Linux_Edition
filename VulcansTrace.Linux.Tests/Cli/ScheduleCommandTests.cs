using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Cli;
using Xunit;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class ScheduleCommandTests : IDisposable
{
    private readonly string _configDir;

    public ScheduleCommandTests()
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"vt-schedule-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_configDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_configDir))
                Directory.Delete(_configDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    [Fact]
    public async Task Main_ScheduleAdd_PersistsAndLogs()
    {
        var result = await Program.Main(["schedule", "add",
            "--config-dir", _configDir,
            "--name", "Nightly Audit",
            "--intent", "FullAudit",
            "--cron", "0 2 * * *"]);

        Assert.Equal(0, result);

        using var schedules = JsonFileScheduleStore.CreateDefault(_configDir);
        var created = Assert.Single(schedules.GetAll());
        Assert.Equal("Nightly Audit", created.Name);
        Assert.Equal("0 2 * * *", created.CronExpression);

        Assert.Contains(GetActions(), a =>
            a.ActionType == AnalystActionType.ScheduleAdded && a.Target == created.Id && a.Actor == "cli");
    }

    [Fact]
    public async Task Main_ScheduleAdd_MissingName_ReturnsError()
    {
        var result = await Program.Main(["schedule", "add",
            "--config-dir", _configDir,
            "--intent", "FullAudit",
            "--cron", "0 2 * * *"]);

        Assert.Equal(1, result);

        using var schedules = JsonFileScheduleStore.CreateDefault(_configDir);
        Assert.Empty(schedules.GetAll());
    }

    [Fact]
    public async Task Main_ScheduleDelete_RemovesAndLogs()
    {
        SeedSchedule("delete-me");

        var result = await Program.Main(["schedule", "delete",
            "--config-dir", _configDir,
            "--id", "delete-me"]);

        Assert.Equal(0, result);

        using var schedules = JsonFileScheduleStore.CreateDefault(_configDir);
        Assert.Empty(schedules.GetAll());

        Assert.Contains(GetActions(), a =>
            a.ActionType == AnalystActionType.ScheduleDeleted && a.Target == "delete-me");
    }

    [Fact]
    public async Task Main_ScheduleDisable_TogglesAndLogs()
    {
        SeedSchedule("toggle-me");

        var result = await Program.Main(["schedule", "disable",
            "--config-dir", _configDir,
            "--id", "toggle-me"]);

        Assert.Equal(0, result);

        using var schedules = JsonFileScheduleStore.CreateDefault(_configDir);
        var updated = Assert.Single(schedules.GetAll());
        Assert.False(updated.Enabled);

        Assert.Contains(GetActions(), a =>
            a.ActionType == AnalystActionType.ScheduleDisabled && a.Target == "toggle-me");
    }

    private void SeedSchedule(string id)
    {
        using var store = JsonFileScheduleStore.CreateDefault(_configDir);
        store.Save(new AuditSchedule
        {
            Id = id,
            Name = id,
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 2 * * *"
        });
    }

    private IReadOnlyList<AnalystActionEntry> GetActions()
    {
        using var store = JsonFileAnalystActionStore.CreateDefault(_configDir);
        return store.GetAll().ToList();
    }
}
