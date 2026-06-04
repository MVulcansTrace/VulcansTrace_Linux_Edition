using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class SyntheticEventSourceTests
{
    [Fact]
    public void DisplayName_IsNotEmpty()
    {
        var source = new SyntheticEventSource();
        Assert.False(string.IsNullOrWhiteSpace(source.DisplayName));
    }

    [Fact]
    public void IsAvailable_IsTrue()
    {
        var source = new SyntheticEventSource();
        Assert.True(source.IsAvailable);
    }

    [Fact]
    public async Task StreamAsync_GeneratesEvents()
    {
        var source = new SyntheticEventSource(seed: 42);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var events = new List<VulcansTrace.Linux.Core.UnifiedEvent>();
        await foreach (var evt in source.StreamAsync(cts.Token))
        {
            events.Add(evt);
            if (events.Count >= 10) break;
        }

        Assert.True(events.Count >= 10);
        Assert.All(events, e =>
        {
            Assert.False(string.IsNullOrWhiteSpace(e.SourceIP));
            Assert.False(string.IsNullOrWhiteSpace(e.DestinationIP));
            Assert.True(e.SourcePort > 0);
            Assert.True(e.DestinationPort > 0);
        });
    }

    [Fact]
    public async Task StreamAsync_Cancellation_StopsGracefully()
    {
        var source = new SyntheticEventSource(seed: 42);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        var events = new List<VulcansTrace.Linux.Core.UnifiedEvent>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var evt in source.StreamAsync(cts.Token))
            {
                events.Add(evt);
            }
        });
    }

    [Fact]
    public async Task StreamAsync_ProducesPortScanLikeBurst()
    {
        // Fast delay + high port scan probability to ensure we see bursts
        var patterns = new SyntheticPatterns
        {
            EventDelayMs = 10,
            PortScanProbability = 1.0,
            PortScanStart = TimeSpan.Zero,
            PortScanEnd = TimeSpan.FromSeconds(10),
            BeaconingEnabled = false,
            FloodEnabled = false
        };

        var source = new SyntheticEventSource(patterns, seed: 42);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        var events = new List<VulcansTrace.Linux.Core.UnifiedEvent>();
        try
        {
            await foreach (var evt in source.StreamAsync(cts.Token))
            {
                events.Add(evt);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when the CTS fires
        }

        // Port scan bursts should produce multiple events from same source rapidly
        Assert.True(events.Count > 0, "Should have captured some events before cancellation");
        var grouped = events.GroupBy(e => e.SourceIP).ToList();
        var maxDistinctPorts = grouped.Max(g => g.Select(e => e.DestinationPort).Distinct().Count());
        Assert.True(maxDistinctPorts > 1, "Should see multiple distinct destination ports from at least one source");
    }
}
