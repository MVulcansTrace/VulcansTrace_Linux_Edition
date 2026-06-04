namespace VulcansTrace.Linux.Core.Live;

/// <summary>
/// Abstraction for a source of real-time <see cref="UnifiedEvent"/> records.
/// Implementations may read from kernel sockets (AF_PACKET, AF_NETLINK),
/// synthetic generators, or replay files.
/// </summary>
public interface IEventSource
{
    /// <summary>
    /// Gets a human-readable name for this source (e.g., "Kernel Packet Capture", "Synthetic Demo").
    /// </summary>
    string DisplayName { get; }

    /// <summary>
    /// Gets whether this source is available on the current platform and privilege level.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Gets an optional reason when <see cref="IsAvailable"/> is false (e.g., "Requires root privileges").
    /// </summary>
    string? UnavailabilityReason { get; }

    /// <summary>
    /// Asynchronously streams <see cref="UnifiedEvent"/> records until cancellation is requested.
    /// The enumerator yields each event as it arrives.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the stream.</param>
    /// <returns>An async enumerable of unified events.</returns>
    IAsyncEnumerable<UnifiedEvent> StreamAsync(CancellationToken cancellationToken);
}
