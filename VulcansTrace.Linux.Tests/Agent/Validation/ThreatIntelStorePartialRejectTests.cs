using System.Text.Json;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public sealed class ThreatIntelStorePartialRejectTests : IDisposable
{
    private readonly string _tempDir;
    private readonly JsonSerializerOptions _caseInsensitive = new() { PropertyNameCaseInsensitive = true };

    public ThreatIntelStorePartialRejectTests()
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
    public void Load_DropsInvalidEntries_KeepsValid_RewritesLiveFile_PreservesOriginal()
    {
        var filePath = Path.Combine(_tempDir, "threatintel.json");
        var iocs = new List<IocEntry>
        {
            new() { Type = IocType.IPv4, Value = "1.2.3.4", Source = "test" },
            new() { Type = IocType.FileHash, Value = "not-hex!", Source = "test" }, // invalid
            new() { Type = IocType.IPv4, Value = "5.6.7.8", Source = "test" },
        };
        File.WriteAllText(filePath, JsonSerializer.Serialize(iocs));

        var store = new JsonFileThreatIntelStore(filePath);

        // (a) warning names the rejected count.
        Assert.NotNull(store.PersistenceWarning);
        Assert.Contains("1 invalid", store.PersistenceWarning);

        // (b) valid IOCs loaded; invalid dropped from memory.
        var loaded = store.GetAll();
        Assert.Equal(2, loaded.Count);
        Assert.DoesNotContain(loaded, e => e.Type == IocType.FileHash);

        // (c) exactly one .corrupt backup of the original.
        var corruptFiles = Directory.GetFiles(_tempDir, "threatintel.corrupt.*.json");
        Assert.Single(corruptFiles);

        // (d) live file rewritten with only the valid IOCs.
        var rewritten = JsonSerializer.Deserialize<List<IocEntry>>(File.ReadAllText(filePath), _caseInsensitive)!;
        Assert.Equal(2, rewritten.Count);
        Assert.DoesNotContain(rewritten, e => e.Type == IocType.FileHash);

        // (e) the quarantined original still holds every entry, including the bad one (recoverable).
        var quarantined = JsonSerializer.Deserialize<List<IocEntry>>(File.ReadAllText(corruptFiles[0]), _caseInsensitive)!;
        Assert.Equal(3, quarantined.Count);
        Assert.Contains(quarantined, e => e.Type == IocType.FileHash);
    }

    [Fact]
    public void Load_AllValid_NoQuarantine_NoWarning()
    {
        var filePath = Path.Combine(_tempDir, "threatintel.json");
        var iocs = new List<IocEntry>
        {
            new() { Type = IocType.IPv4, Value = "1.2.3.4", Source = "test" },
            new() { Type = IocType.IPv4, Value = "5.6.7.8", Source = "test" },
        };
        File.WriteAllText(filePath, JsonSerializer.Serialize(iocs));

        var store = new JsonFileThreatIntelStore(filePath);

        Assert.Null(store.PersistenceWarning);
        Assert.Equal(2, store.GetAll().Count);
        Assert.Empty(Directory.GetFiles(_tempDir, "threatintel.corrupt.*.json"));
    }
}
