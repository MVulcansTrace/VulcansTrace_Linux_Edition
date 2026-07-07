using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Agent;

/// <summary>
/// Tests for the config-directory override. These are the only writer/reader of
/// <see cref="VulcansTraceConfig"/>'s process-wide override in the suite (every other test passes an
/// explicit config dir), and xUnit runs a class's tests sequentially, so the static is safe here.
/// </summary>
public class VulcansTraceConfigTests
{
    [Fact]
    public void GetDirectory_AppendsVulcansTraceSegment()
    {
        var dir = VulcansTraceConfig.GetDirectory("/tmp/vt-test-base");
        Assert.EndsWith("VulcansTrace", dir);
        Assert.Contains("vt-test-base", dir);
    }

    [Fact]
    public void GetDirectory_ExplicitDirectory_BeatsOverride()
    {
        VulcansTraceConfig.OverrideDirectory = "/tmp/vt-override";
        try
        {
            var dir = VulcansTraceConfig.GetDirectory("/tmp/vt-explicit");
            Assert.Contains("vt-explicit", dir);
            Assert.DoesNotContain("vt-override", dir);
        }
        finally
        {
            VulcansTraceConfig.OverrideDirectory = null;
        }
    }

    [Fact]
    public void GetDirectory_OverrideDirectory_IsUsedWhenNoExplicitArg()
    {
        VulcansTraceConfig.OverrideDirectory = "/tmp/vt-override-xyz";
        try
        {
            var dir = VulcansTraceConfig.GetDirectory();
            Assert.Contains("vt-override-xyz", dir);
            Assert.EndsWith("VulcansTrace", dir);
        }
        finally
        {
            VulcansTraceConfig.OverrideDirectory = null;
        }
    }

    [Fact]
    public void OverrideDirectory_RoutesStoreCreateDefault_WhenNoExplicitArg()
    {
        // This is the mechanism the --config-dir flag relies on: Main sets OverrideDirectory, and
        // stores created with no explicit dir resolve through it.
        var tempDir = Path.Combine(Path.GetTempPath(), $"vt-cfg-{Guid.NewGuid():N}");
        VulcansTraceConfig.OverrideDirectory = tempDir;
        try
        {
            using var store = JsonFileScheduleStore.CreateDefault();
            store.Save(new AuditSchedule
            {
                Id = "test-001",
                Name = "Test",
                Intent = AgentIntent.FullAudit,
                CronExpression = "0 6 * * *"
            });

            // The store was rooted at the override dir: the schedule file lands there, not in the
            // operator's real config.
            Assert.True(File.Exists(Path.Combine(tempDir, "VulcansTrace", "schedules.json")));
        }
        finally
        {
            VulcansTraceConfig.OverrideDirectory = null;
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void AgentFactory_ExplicitDirectory_RoutesYaraCustomRules()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"vt-cfg-{Guid.NewGuid():N}");
        try
        {
            using var services = AgentFactory.Create(configDirectory: tempDir);

            var yaraScanner = Assert.Single(services.DoctorService.Scanners.OfType<YaraScanner>());

            Assert.Equal(Path.Combine(tempDir, "VulcansTrace", "yara"), yaraScanner.CustomRulesDirectory);
        }
        finally
        {
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void AgentFactory_PolicyStoreFallsBackToSessionOnlyStore_WhenPolicyPersistenceUnavailable()
    {
        var blockingFile = Path.GetTempFileName();
        try
        {
            using var services = AgentFactory.Create(configDirectory: blockingFile);

            Assert.NotNull(services.PolicyStore);

            var save = services.PolicyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { Enabled = false });

            Assert.Equal(RulePolicySaveOutcome.SessionOnly, save.Outcome);
            Assert.Contains("session", save.Message, StringComparison.OrdinalIgnoreCase);
            Assert.False(services.PolicyProvider.GetPolicy("TEST-001", MachineRole.Server)!.Enabled);
        }
        finally
        {
            try { File.Delete(blockingFile); } catch { }
        }
    }
}
