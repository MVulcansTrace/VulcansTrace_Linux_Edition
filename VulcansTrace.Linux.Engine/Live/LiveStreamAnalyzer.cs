using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Engine.Configuration;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Orchestrates live stream analysis: consumes an <see cref="IEventSource"/>,
/// buffers events into a <see cref="LiveStreamWindow"/>, periodically runs
/// <see cref="SentryAnalyzer"/>, and emits deduplicated <see cref="LiveAnalysisResult"/> records.
/// </summary>
public sealed class LiveStreamAnalyzer : IDisposable
{
    private readonly SentryAnalyzer _analyzer;
    private readonly AnalysisProfileProvider _profileProvider;
    private readonly ILogSink _logSink;
    private readonly TimeSpan _timeWindow;
    private readonly int _maxCount;
    private readonly TimeSpan _analysisInterval;
    private readonly int _analysisEventThreshold;
    private readonly TimeSpan _fingerprintTtl;

    private readonly ConcurrentDictionary<string, DateTime> _seenFingerprints = new();
    private CancellationTokenSource? _cts;
    private Task? _pipelineTask;
    private IEventSource? _currentSource;
    private int _analysisRunCount;
    private bool _disposed;

    /// <summary>
    /// Channel that broadcasts live analysis results. Bounded to prevent back-pressure.
    /// </summary>
    private readonly Channel<LiveAnalysisResult> _resultChannel;

    /// <summary>
    /// Raised when the live pipeline fails outside normal cancellation.
    /// </summary>
    public event EventHandler<Exception>? StreamFaulted;

    /// <summary>
    /// Raised whenever a live analysis window completes.
    /// </summary>
    public event EventHandler<LiveAnalysisResult>? ResultProduced;

    /// <summary>
    /// Initializes a new instance of the <see cref="LiveStreamAnalyzer"/> class.
    /// </summary>
    public LiveStreamAnalyzer(
        SentryAnalyzer analyzer,
        AnalysisProfileProvider profileProvider,
        ILogSink? logSink = null,
        TimeSpan? timeWindow = null,
        int? maxCount = null,
        TimeSpan? analysisInterval = null,
        int? analysisEventThreshold = null,
        TimeSpan? fingerprintTtl = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _profileProvider = profileProvider ?? throw new ArgumentNullException(nameof(profileProvider));
        _logSink = logSink ?? NullLogSink.Instance;
        _timeWindow = timeWindow ?? TimeSpan.FromSeconds(60);
        _maxCount = maxCount ?? 10_000;
        _analysisInterval = analysisInterval ?? TimeSpan.FromSeconds(5);
        _analysisEventThreshold = analysisEventThreshold ?? 500;
        _fingerprintTtl = fingerprintTtl ?? TimeSpan.FromMinutes(5);
        // Use DropOldest so the pipeline never stalls when the UI consumer
        // lags behind. Live analysis should prioritize fresh results.
        _resultChannel = Channel.CreateBounded<LiveAnalysisResult>(new BoundedChannelOptions(64)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });
    }

    /// <summary>
    /// Async enumerable of live analysis results. Yields each time a new analysis window completes.
    /// </summary>
    public IAsyncEnumerable<LiveAnalysisResult> ResultsAsync(CancellationToken cancellationToken = default)
    {
        return _resultChannel.Reader.ReadAllAsync(cancellationToken);
    }

    /// <summary>
    /// Starts the live analysis pipeline with the given event source and intensity.
    /// </summary>
    public void Start(IEventSource source, IntensityLevel intensity)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(source);

        Stop();

        _currentSource = source;
        _cts = new CancellationTokenSource();
        _pipelineTask = RunPipelineAsync(source, intensity, _cts.Token);
    }

    /// <summary>
    /// Stops the live analysis pipeline and clears internal state.
    /// This is a fast, non-blocking cancellation; callers that need to await
    /// graceful shutdown should use <see cref="StopAsync"/>.
    /// </summary>
    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        // Dispose the event source to unblock any blocking recv() calls
        (_currentSource as IDisposable)?.Dispose();
        _currentSource = null;

        _pipelineTask = null;
        _seenFingerprints.Clear();
        _analysisRunCount = 0;
    }

    /// <summary>
    /// Asynchronously stops the live analysis pipeline, awaiting its completion
    /// (with a timeout) so the caller can perform graceful shutdown without
    /// blocking the calling thread.
    /// </summary>
    public async Task StopAsync()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        // Dispose the event source to unblock any blocking recv() calls
        (_currentSource as IDisposable)?.Dispose();
        _currentSource = null;

        if (_pipelineTask != null)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await _pipelineTask.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Timeout or expected cancellation
            }
            catch (Exception ex)
            {
                _logSink.Write(LogLevel.Warning, $"Live stream pipeline shutdown error: {ex.Message}");
            }
            _pipelineTask = null;
        }

        _seenFingerprints.Clear();
        _analysisRunCount = 0;
    }

    private async Task RunPipelineAsync(IEventSource source, IntensityLevel intensity, CancellationToken cancellationToken)
    {
        var window = new LiveStreamWindow(_timeWindow, _maxCount);
        var profile = _profileProvider.GetProfile(intensity);
        var lastAnalysisTime = DateTime.UtcNow;
        int eventsSinceAnalysis = 0;

        _logSink.Write(LogLevel.Info, $"Live stream started: {source.DisplayName}");

        try
        {
            await foreach (var evt in source.StreamAsync(cancellationToken).ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();

                window.Add(evt);
                eventsSinceAnalysis++;

                var now = DateTime.UtcNow;
                bool shouldAnalyze =
                    (now - lastAnalysisTime) >= _analysisInterval ||
                    eventsSinceAnalysis >= _analysisEventThreshold;

                if (shouldAnalyze)
                {
                    await AnalyzeWindowAsync(window, source.DisplayName, intensity, profile, cancellationToken).ConfigureAwait(false);
                    lastAnalysisTime = now;
                    eventsSinceAnalysis = 0;
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logSink.Write(LogLevel.Info, "Live stream cancelled.");
        }
        catch (Exception ex)
        {
            _logSink.Write(LogLevel.Error, $"Live stream pipeline error: {ex.Message}", ex);
            StreamFaulted?.Invoke(this, ex);
        }
        finally
        {
            await AnalyzeWindowAsync(window, source.DisplayName, intensity, profile, CancellationToken.None).ConfigureAwait(false);
            window.Clear();
            if (ReferenceEquals(_currentSource, source))
            {
                (_currentSource as IDisposable)?.Dispose();
                _currentSource = null;
            }
        }
    }

    private async Task AnalyzeWindowAsync(LiveStreamWindow window, string sourceName, IntensityLevel intensity, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        var snapshot = window.Snapshot();
        if (snapshot.Count == 0)
            return;

        var metrics = window.GetMetrics();

        AnalysisResult result;
        try
        {
            // Use the structured-event overload to avoid lossy string round-trip
            result = await Task.Run(
                () => _analyzer.Analyze(snapshot, intensity, cancellationToken, profile),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logSink.Write(LogLevel.Error, $"Live analysis error: {ex.Message}", ex);
            return;
        }

        // Deduplicate findings by fingerprint
        var delta = new List<Finding>();
        foreach (var finding in result.Findings)
        {
            var fp = finding.Fingerprint;
            var now = DateTime.UtcNow;

            if (_seenFingerprints.TryGetValue(fp, out var lastSeen))
            {
                if (now - lastSeen < _fingerprintTtl)
                {
                    continue; // Still within TTL, suppress
                }
            }

            _seenFingerprints[fp] = now;
            delta.Add(finding);
        }

        // Prune expired fingerprints to prevent unbounded growth
        PruneExpiredFingerprints();

        _analysisRunCount++;

        var liveResult = new LiveAnalysisResult
        {
            Analysis = result,
            DeltaFindings = delta,
            WindowMetrics = metrics,
            AnalysisRunCount = _analysisRunCount,
            SourceName = sourceName
        };

        await _resultChannel.Writer.WriteAsync(liveResult, cancellationToken).ConfigureAwait(false);
        ResultProduced?.Invoke(this, liveResult);
    }

    private void PruneExpiredFingerprints()
    {
        var now = DateTime.UtcNow;
        var expired = _seenFingerprints
            .Where(kvp => now - kvp.Value >= _fingerprintTtl)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in expired)
        {
            _seenFingerprints.TryRemove(key, out _);
        }
    }

    private static string FormatAsIptablesLog(UnifiedEvent e)
    {
        // Minimal iptables-like format for parser compatibility
        var mac = e.LinuxSpecific.TryGetValue("MAC", out var m) ? m : "00:00:00:00:00:00";
        var flags = e.LinuxSpecific.TryGetValue("FLAGS", out var f) ? f : "SYN";
        var len = e.LinuxSpecific.TryGetValue("LEN", out var l) ? l : "60";
        var ttl = e.LinuxSpecific.TryGetValue("TTL", out var t) ? t : "64";

        return $"kernel: {e.Timestamp:MMM dd HH:mm:ss} host {e.Action}: IN=eth0 OUT= MAC={mac} SRC={e.SourceIP} DST={e.DestinationIP} LEN={len} TTL={ttl} PROTO={e.Protocol} SPT={e.SourcePort} DPT={e.DestinationPort} WINDOW=64240 RES=0x00 {flags}";
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Stop();
        _resultChannel.Writer.TryComplete();
    }
}
