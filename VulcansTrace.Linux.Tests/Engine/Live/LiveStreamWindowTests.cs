using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class LiveStreamWindowTests
{
    [Fact]
    public void Add_SingleEvent_SnapshotContainsEvent()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 100);
        var evt = CreateEvent(DateTime.UtcNow, "10.0.0.1", "10.0.0.2");

        window.Add(evt);
        var snapshot = window.Snapshot();

        Assert.Single(snapshot);
        Assert.Equal("10.0.0.1", snapshot[0].SourceIP);
    }

    [Fact]
    public void AddRange_MultipleEvents_SnapshotContainsAll()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 100);
        var events = Enumerable.Range(0, 5).Select(i => CreateEvent(DateTime.UtcNow, $"10.0.0.{i}", "10.0.0.99"));

        window.AddRange(events);
        var snapshot = window.Snapshot();

        Assert.Equal(5, snapshot.Count);
    }

    [Fact]
    public void Snapshot_EvictsEventsOutsideTimeWindow()
    {
        var window = new LiveStreamWindow(TimeSpan.FromSeconds(2), 100);
        var oldEvent = CreateEvent(DateTime.UtcNow.AddSeconds(-5), "10.0.0.1", "10.0.0.2");
        var newEvent = CreateEvent(DateTime.UtcNow, "10.0.0.3", "10.0.0.4");

        window.Add(oldEvent);
        window.Add(newEvent);
        var snapshot = window.Snapshot();

        Assert.Single(snapshot);
        Assert.Equal("10.0.0.3", snapshot[0].SourceIP);
    }

    [Fact]
    public void Snapshot_EvictsEventsExceedingCountCap()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(10), 3);
        var events = Enumerable.Range(0, 5).Select(i => CreateEvent(DateTime.UtcNow.AddMilliseconds(i), $"10.0.0.{i}", "10.0.0.99"));

        window.AddRange(events);
        var snapshot = window.Snapshot();

        Assert.Equal(3, snapshot.Count);
        // Oldest events should be evicted; newest retained
        Assert.Equal("10.0.0.2", snapshot[0].SourceIP);
        Assert.Equal("10.0.0.4", snapshot[2].SourceIP);
    }

    [Fact]
    public void Clear_RemovesAllEvents()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 100);
        window.Add(CreateEvent(DateTime.UtcNow, "10.0.0.1", "10.0.0.2"));
        window.Clear();

        var snapshot = window.Snapshot();
        Assert.Empty(snapshot);
    }

    [Fact]
    public void GetMetrics_EmptyWindow_ReturnsZeroMetrics()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 100);
        var metrics = window.GetMetrics();

        Assert.Equal(0, metrics.EventCount);
        Assert.Equal(0, metrics.UniqueSourceCount);
        Assert.Equal(0, metrics.EventsPerSecond);
    }

    [Fact]
    public void GetMetrics_ComputesCorrectCounts()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 100);
        var events = new[]
        {
            CreateEvent(DateTime.UtcNow, "10.0.0.1", "10.0.0.2", len: "60"),
            CreateEvent(DateTime.UtcNow, "10.0.0.1", "10.0.0.3", len: "100"),
            CreateEvent(DateTime.UtcNow, "10.0.0.2", "10.0.0.2", len: "40"),
        };

        window.AddRange(events);
        var metrics = window.GetMetrics();

        Assert.Equal(3, metrics.EventCount);
        Assert.Equal(200, metrics.TotalBytes);
        Assert.Equal(2, metrics.UniqueSourceCount);
        Assert.Equal(2, metrics.UniqueDestinationCount);
    }

    [Fact]
    public async Task Add_ConcurrentStress_DoesNotThrow()
    {
        var window = new LiveStreamWindow(TimeSpan.FromMinutes(1), 1000);
        var tasks = Enumerable.Range(0, 10).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < 100; i++)
            {
                window.Add(CreateEvent(DateTime.UtcNow, $"10.0.0.{i % 256}", "10.0.0.99"));
            }
        })).ToArray();

        await Task.WhenAll(tasks);
        var snapshot = window.Snapshot();

        // Count cap should have been applied
        Assert.True(snapshot.Count <= 1000);
    }

    private static UnifiedEvent CreateEvent(DateTime timestamp, string src, string dst, string len = "60")
    {
        return new UnifiedEvent
        {
            Timestamp = timestamp,
            SourceIP = src,
            SourcePort = 12345,
            DestinationIP = dst,
            DestinationPort = 80,
            Protocol = "TCP",
            Action = "DROP",
            LogFormat = LogFormat.Iptables,
            LinuxSpecific = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["LEN"] = len
            }
        };
    }
}
