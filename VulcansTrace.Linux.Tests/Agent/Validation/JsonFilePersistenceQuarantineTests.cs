using VulcansTrace.Linux.Agent.Persistence;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class JsonFilePersistenceQuarantineTests : IDisposable
{
    private readonly string _tempDir;

    public JsonFilePersistenceQuarantineTests()
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
    public void Quarantine_WhenFileExists_MovesItAsideAndReturnsPath()
    {
        var filePath = Path.Combine(_tempDir, "test.json");
        File.WriteAllText(filePath, "{\"hello\":\"world\"}");

        var persistence = new JsonFilePersistence<object>(filePath);
        var quarantinePath = persistence.Quarantine();

        Assert.NotNull(quarantinePath);
        Assert.True(File.Exists(quarantinePath), "Quarantine file should exist.");
        Assert.False(File.Exists(filePath), "Original file should no longer exist.");
        Assert.Contains(".corrupt.", quarantinePath);
    }

    [Fact]
    public void Quarantine_WhenFileMissing_ReturnsNull()
    {
        var filePath = Path.Combine(_tempDir, "missing.json");
        var persistence = new JsonFilePersistence<object>(filePath);

        var quarantinePath = persistence.Quarantine();

        Assert.Null(quarantinePath);
    }

    [Fact]
    public void Quarantine_MultipleTimes_CreatesUniquePaths()
    {
        var filePath = Path.Combine(_tempDir, "test.json");
        File.WriteAllText(filePath, "{\"hello\":\"world\"}");

        var persistence = new JsonFilePersistence<object>(filePath);
        var first = persistence.Quarantine();
        File.WriteAllText(filePath, "{\"hello\":\"again\"}");
        var second = persistence.Quarantine();

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotEqual(first, second);
        Assert.True(File.Exists(first));
        Assert.True(File.Exists(second));
    }
}
