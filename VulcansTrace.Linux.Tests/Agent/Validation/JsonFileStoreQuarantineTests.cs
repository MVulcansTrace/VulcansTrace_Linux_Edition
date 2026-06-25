using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scheduling;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class JsonFileStoreQuarantineTests : IDisposable
{
    private readonly string _tempDir;

    public JsonFileStoreQuarantineTests()
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
    public void SuppressionStore_Load_CorruptJson_QuarantinesFileAndSetsWarning()
    {
        var filePath = Path.Combine(_tempDir, "suppressions.json");
        File.WriteAllText(filePath, "THIS IS NOT JSON {{{}");

        var store = new JsonFileSuppressionStore(filePath);

        Assert.NotNull(store.PersistenceWarning);
        Assert.Empty(store.GetAllRaw());

        var quarantineFiles = Directory.GetFiles(_tempDir, "suppressions.corrupt.*.json");
        Assert.Single(quarantineFiles);
    }

    [Fact]
    public void ScheduleStore_Load_InvalidCronExpression_QuarantinesFileAndSetsWarning()
    {
        var filePath = Path.Combine(_tempDir, "schedules.json");
        // Deserializes successfully but fails cron-expression validation.
        File.WriteAllText(filePath, "[{\"Id\":\"sched-1\",\"Name\":\"Bad\",\"Intent\":0,\"CronExpression\":\"not-a-cron\"}]");

        var store = new JsonFileScheduleStore(filePath);

        Assert.NotNull(store.PersistenceWarning);
        Assert.Empty(store.GetAll());

        var quarantineFiles = Directory.GetFiles(_tempDir, "schedules.corrupt.*.json");
        Assert.Single(quarantineFiles);
    }
}
