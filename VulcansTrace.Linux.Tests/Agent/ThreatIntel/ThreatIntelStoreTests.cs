using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.ThreatIntel;

public class ThreatIntelStoreTests
{
    [Fact]
    public void InMemoryStore_ImportAndRetrieve()
    {
        var store = new InMemoryThreatIntelStore();
        Assert.Equal(0, store.Count);

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", ThreatScore = 80, Source = "STIX" },
            new IocEntry { Type = IocType.Port, Value = "4444", ThreatScore = 60, Source = "STIX" }
        });

        Assert.Equal(2, store.Count);
        Assert.Equal(1, store.CountByType(IocType.IPv4));
        Assert.Equal(1, store.CountByType(IocType.Port));

        var ips = store.GetByType(IocType.IPv4);
        Assert.Single(ips);
        Assert.Equal("192.168.1.1", ips[0].Value);
    }

    [Fact]
    public void InMemoryStore_Clear_RemovesAll()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[] { new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4" } });
        store.Clear();
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void InMemoryStore_DeduplicatesByKey()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 50 },
            new IocEntry { Type = IocType.IPv4, Value = "1.2.3.4", ThreatScore = 90 }
        });

        Assert.Equal(1, store.Count);
        Assert.Equal(90, store.GetAll()[0].ThreatScore);
    }

    [Fact]
    public void JsonFileStore_Persistence_RoundTrip()
    {
        var path = Path.GetTempFileName();
        try
        {
            var store1 = new JsonFileThreatIntelStore(path);
            store1.Import(new[]
            {
                new IocEntry { Type = IocType.IPv4, Value = "10.0.0.1", ThreatScore = 70, Source = "MISP" }
            });
            store1.Dispose();

            var store2 = new JsonFileThreatIntelStore(path);
            Assert.Equal(1, store2.Count);
            Assert.Equal("10.0.0.1", store2.GetByType(IocType.IPv4)[0].Value);
            store2.Dispose();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void JsonFileStore_CreateDefault_DoesNotThrow()
    {
        var tempConfigDir = Path.Combine(Path.GetTempPath(), $"vt-ti-test-{Guid.NewGuid():N}");
        try
        {
            var store = JsonFileThreatIntelStore.CreateDefault(tempConfigDir);
            Assert.NotNull(store);
            store.Dispose();
        }
        finally
        {
            try { if (Directory.Exists(tempConfigDir)) Directory.Delete(tempConfigDir, recursive: true); }
            catch { /* best-effort cleanup */ }
        }
    }
}
