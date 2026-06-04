using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class KernelSourceTests
{
    [Fact]
    public void NativeSocket_IsRoot_ReturnsFalseForNonRoot()
    {
        // In CI and normal development we are not root
        Assert.False(NativeSocket.IsRoot());
    }

    [Fact]
    public void PacketCaptureEventSource_IsAvailable_MatchesRootStatus()
    {
        var source = new PacketCaptureEventSource();
        Assert.Equal(NativeSocket.IsRoot(), source.IsAvailable);
    }

    [Fact]
    public void PacketCaptureEventSource_UnavailabilityReason_NotNullWhenUnavailable()
    {
        var source = new PacketCaptureEventSource();
        if (!source.IsAvailable)
        {
            Assert.NotNull(source.UnavailabilityReason);
            Assert.False(string.IsNullOrWhiteSpace(source.UnavailabilityReason));
        }
    }

    [Fact]
    public void NflogEventSource_IsAvailable_MatchesRootStatus()
    {
        var source = new NflogEventSource();
        Assert.Equal(NativeSocket.IsRoot(), source.IsAvailable);
    }

    [Fact]
    public void NflogEventSource_UnavailabilityReason_NotNullWhenUnavailable()
    {
        var source = new NflogEventSource();
        if (!source.IsAvailable)
        {
            Assert.NotNull(source.UnavailabilityReason);
            Assert.False(string.IsNullOrWhiteSpace(source.UnavailabilityReason));
        }
    }

    [Fact]
    public async Task PacketCaptureEventSource_StreamAsync_ThrowsWithoutRoot()
    {
        if (NativeSocket.IsRoot())
            return; // Skip when running as root

        var source = new PacketCaptureEventSource();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (var _ in source.StreamAsync(CancellationToken.None))
            {
                // Should not reach here
            }
        });
    }

    [Fact]
    public async Task NflogEventSource_StreamAsync_ThrowsWithoutRoot()
    {
        if (NativeSocket.IsRoot())
            return; // Skip when running as root

        var source = new NflogEventSource();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (var _ in source.StreamAsync(CancellationToken.None))
            {
                // Should not reach here
            }
        });
    }

    [Fact]
    public async Task PacketCaptureEventSource_StreamAsync_CanOpenSocketWhenRoot()
    {
        if (!NativeSocket.IsRoot())
            return; // Skip when not running as root

        var source = new PacketCaptureEventSource();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

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
            // Expected
        }

        // We may or may not get events depending on traffic, but socket creation should succeed
        Assert.True(true);
    }
}
