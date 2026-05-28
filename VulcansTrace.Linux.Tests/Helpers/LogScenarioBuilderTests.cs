using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Helpers;

public class LogScenarioBuilderTests
{
    private readonly LogNormalizer _normalizer = new();

    [Fact]
    public void BuildPortScan_ProducesDistinctPorts()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildPortScan(targetCount: 100, duration: TimeSpan.FromMinutes(3)).Generate();
        var events = _normalizer.Normalize(log).Events;

        var distinctPorts = events.Select(e => e.DestinationPort).Distinct().Count();
        Assert.Equal(100, distinctPorts);
    }

    [Fact]
    public void BuildPortScan_ProducesCorrectEventCount()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(1)).Generate();
        var events = _normalizer.Normalize(log).Events;

        Assert.Equal(20, events.Length);
    }

    [Fact]
    public void BuildBeaconing_ProducesCorrectEventCount()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildBeaconing(interval: TimeSpan.FromSeconds(30), duration: TimeSpan.FromMinutes(5)).Generate();
        var events = _normalizer.Normalize(log).Events;

        Assert.Equal(10, events.Length);
    }

    [Fact]
    public void BuildBeaconing_ProducesRegularIntervals()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildBeaconing(interval: TimeSpan.FromSeconds(60), duration: TimeSpan.FromMinutes(10)).Generate();
        var events = _normalizer.Normalize(log).Events;

        for (int i = 1; i < events.Length; i++)
        {
            var diff = (events[i].Timestamp - events[i - 1].Timestamp).TotalSeconds;
            Assert.True(Math.Abs(diff - 60) < 1, $"Expected ~60s interval, got {diff}s");
        }
    }

    [Fact]
    public void BuildUnusualPacketSizes_ProducesCorrectCounts()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildUnusualPacketSizes(largeCount: 5, smallCount: 3, consistentCount: 10).Generate();
        var events = _normalizer.Normalize(log).Events;

        Assert.Equal(18, events.Length);
    }

    [Fact]
    public void BuildInterfaceHopping_ProducesCorrectCount()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildInterfaceHopping(
            interfaces: new[] { "eth0", "eth1", "wlan0" },
            interval: TimeSpan.FromMinutes(1)).Generate();
        var events = _normalizer.Normalize(log).Events;

        Assert.Equal(3, events.Length);
    }

    [Fact]
    public void BuildPortScan_AllEventsAreIptables()
    {
        var builder = new LogScenarioBuilder();
        var log = builder.BuildPortScan(targetCount: 10, duration: TimeSpan.FromMinutes(1)).Generate();
        var events = _normalizer.Normalize(log).Events;

        Assert.All(events, e => Assert.Equal(LogFormat.Iptables, e.LogFormat));
    }
}
