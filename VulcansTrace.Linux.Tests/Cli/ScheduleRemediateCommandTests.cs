using System.Text.Json;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Cli;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Cli;

public class ScheduleRemediateCommandTests : IDisposable
{
    private readonly string _tempConfigDir;

    public ScheduleRemediateCommandTests()
    {
        // Each test gets its own isolated config root, injected through the store/factory seams —
        // no mutation of the process-wide XDG_CONFIG_HOME, so the class is fully parallel-safe.
        _tempConfigDir = Path.Combine(Path.GetTempPath(), $"vt-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempConfigDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempConfigDir))
                Directory.Delete(_tempConfigDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    [Fact]
    public async Task RunScheduleRemediateAsync_DisabledSchedule_ReturnsError()
    {
        var schedule = CreateSchedule(allowRemediate: false);
        SaveSchedule(schedule);

        var exitCode = await Program.RunScheduleRemediateAsync(new[] { "schedule", "remediate", "--id", schedule.Id }, _tempConfigDir);

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunScheduleRemediateAsync_MissingSchedule_ReturnsError()
    {
        var exitCode = await Program.RunScheduleRemediateAsync(new[] { "schedule", "remediate", "--id", "nonexistent" }, _tempConfigDir);

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunScheduleRemediateAsync_NoFindings_ReturnsZero()
    {
        var schedule = CreateSchedule(allowRemediate: true, intent: AgentIntent.ThreatIntelCheck);
        SaveSchedule(schedule);

        var exitCode = await Program.RunScheduleRemediateAsync(new[] { "schedule", "remediate", "--id", schedule.Id }, _tempConfigDir);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task RunScheduleRemediateAsync_DryRun_ReturnsZero()
    {
        var schedule = CreateSchedule(allowRemediate: true);
        SaveSchedule(schedule);

        var exitCode = await Program.RunScheduleRemediateAsync(new[] { "schedule", "remediate", "--id", schedule.Id, "--dry-run" }, _tempConfigDir);

        Assert.Equal(0, exitCode);
    }

    private static AuditSchedule CreateSchedule(bool allowRemediate, AgentIntent intent = AgentIntent.FullAudit)
    {
        return new AuditSchedule
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = "Test Schedule",
            Intent = intent,
            CronExpression = "0 6 * * *",
            MachineRole = MachineRole.Workstation,
            AllowAutoRemediate = allowRemediate,
            AllowRemediationRestart = false,
            AllowRemediationPackages = false,
            AllowedRemediationRulePrefixes = Array.Empty<string>()
        };
    }

    private void SaveSchedule(AuditSchedule schedule)
    {
        var store = JsonFileScheduleStore.CreateDefault(_tempConfigDir);
        store.Save(schedule);
        store.Dispose();
    }
}
