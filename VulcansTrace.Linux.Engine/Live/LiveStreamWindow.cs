using System.Collections.Immutable;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Thread-safe rolling buffer of <see cref="UnifiedEvent"/> records.
/// Evicts events older than the time window or when the count cap is exceeded.
/// </summary>
public sealed class LiveStreamWindow
{
    private readonly object _lock = new();
    private readonly List<UnifiedEvent> _events = new();
    private readonly TimeSpan _timeWindow;
    private readonly int _maxCount;

    /// <summary>
    /// Initializes a new instance of the <see cref="LiveStreamWindow"/> class.
    /// </summary>
    /// <param name="timeWindow">Maximum age of events to retain.</param>
    /// <param name="maxCount">Hard cap on the number of events retained.</param>
    public LiveStreamWindow(TimeSpan timeWindow, int maxCount)
    {
        _timeWindow = timeWindow;
        _maxCount = maxCount;
    }

    /// <summary>
    /// Adds an event to the window and evicts stale events.
    /// </summary>
    public void Add(UnifiedEvent evt)
    {
        lock (_lock)
        {
            _events.Add(evt);
            EvictLocked();
        }
    }

    /// <summary>
    /// Adds a batch of events to the window.
    /// </summary>
    public void AddRange(IEnumerable<UnifiedEvent> events)
    {
        lock (_lock)
        {
            _events.AddRange(events);
            EvictLocked();
        }
    }

    /// <summary>
    /// Returns a snapshot of the current window contents.
    /// </summary>
    public IReadOnlyList<UnifiedEvent> Snapshot()
    {
        lock (_lock)
        {
            EvictLocked();
            return _events.ToImmutableList();
        }
    }

    /// <summary>
    /// Clears all events from the window.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _events.Clear();
        }
    }

    /// <summary>
    /// Computes current window metrics.
    /// </summary>
    public LiveWindowMetrics GetMetrics()
    {
        lock (_lock)
        {
            EvictLocked();

            if (_events.Count == 0)
            {
                return new LiveWindowMetrics();
            }

            var oldest = _events[0].Timestamp;
            var newest = _events[_events.Count - 1].Timestamp;
            var duration = newest - oldest;
            var seconds = duration.TotalSeconds;
            var eps = seconds > 0 ? _events.Count / seconds : 0;

            var srcSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dstSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long totalBytes = 0;

            foreach (var e in _events)
            {
                srcSet.Add(e.SourceIP);
                dstSet.Add(e.DestinationIP);
                if (e.LinuxSpecific.TryGetValue("LEN", out var lenStr) && int.TryParse(lenStr, out var len))
                {
                    totalBytes += len;
                }
            }

            return new LiveWindowMetrics
            {
                EventCount = _events.Count,
                TotalBytes = totalBytes,
                WindowDuration = duration,
                UniqueSourceCount = srcSet.Count,
                UniqueDestinationCount = dstSet.Count,
                EventsPerSecond = eps
            };
        }
    }

    private void EvictLocked()
    {
        if (_events.Count == 0)
            return;

        var cutoff = DateTime.UtcNow - _timeWindow;

        // Remove events older than the time window
        int firstValid = 0;
        while (firstValid < _events.Count && _events[firstValid].Timestamp < cutoff)
        {
            firstValid++;
        }

        if (firstValid > 0)
        {
            _events.RemoveRange(0, firstValid);
        }

        // Remove oldest events if count exceeds cap
        if (_events.Count > _maxCount)
        {
            _events.RemoveRange(0, _events.Count - _maxCount);
        }
    }
}
