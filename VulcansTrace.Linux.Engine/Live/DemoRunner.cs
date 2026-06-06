using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;

namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Orchestrates a headless demo run using the live-stream pipeline.
/// </summary>
public sealed class DemoRunner
{
    private readonly LiveStreamAnalyzer _analyzer;
    private readonly TraceMapCorrelator _traceMapCorrelator;

    /// <summary>
    /// Initializes a new instance of the <see cref="DemoRunner"/> class.
    /// </summary>
    /// <param name="analyzer">The live-stream analyzer to use. The runner does not take ownership; the caller is responsible for disposal.</param>
    /// <param name="traceMapCorrelator">Optional trace-map correlator. A new instance is created if null.</param>
    public DemoRunner(LiveStreamAnalyzer analyzer, TraceMapCorrelator? traceMapCorrelator = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _traceMapCorrelator = traceMapCorrelator ?? new TraceMapCorrelator();
    }

    /// <summary>
    /// Runs a demo scenario for the specified duration, collects findings, and returns the aggregated result.
    /// </summary>
    public async Task<DemoResult> RunAsync(
        DemoScenario scenario,
        TimeSpan duration,
        IntensityLevel intensity,
        int? seed = null,
        CancellationToken cancellationToken = default)
    {
        var patterns = DemoPatterns.For(scenario);
        var source = new SyntheticEventSource(patterns, seed);

        var latestFindings = new List<Finding>();
        var findingsLock = new object();
        var startTime = DateTime.UtcNow;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        void OnResultProduced(object? sender, LiveAnalysisResult result)
        {
            lock (findingsLock)
            {
                latestFindings = result.Analysis.Findings.ToList();
            }
        }

        _analyzer.ResultProduced += OnResultProduced;
        _analyzer.Start(source, intensity);

        try
        {
            await Task.Delay(duration, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // External cancellation — propagate after cleanup
        }

        try
        {
            await _analyzer.StopAsync().ConfigureAwait(false);
        }
        finally
        {
            _analyzer.ResultProduced -= OnResultProduced;
            cts.Cancel();
        }

        var endTime = DateTime.UtcNow;
        List<Finding> findingsSnapshot;
        lock (findingsLock)
        {
            findingsSnapshot = latestFindings.ToList();
        }

        var traceMap = _traceMapCorrelator.Correlate(findingsSnapshot);

        var result = new AnalysisResult
        {
            Findings = findingsSnapshot,
            TimeRangeStart = startTime,
            TimeRangeEnd = endTime,
            TotalLines = 0,
            ParsedLines = 0,
            Warnings = Array.Empty<string>(),
            ParseErrors = Array.Empty<string>(),
            ActiveSuppressions = Array.Empty<SuppressionSummary>()
        };

        var rawLogDescription = $"Synthetic demo: {scenario}, duration={duration.TotalSeconds}s, intensity={intensity}, seed={seed?.ToString() ?? "null"}";
        var actualDuration = endTime - startTime;

        return new DemoResult
        {
            AnalysisResult = result,
            TraceMap = traceMap,
            RawLogDescription = rawLogDescription,
            Scenario = scenario,
            Duration = actualDuration,
            Intensity = intensity,
            StartTime = startTime,
            EndTime = endTime
        };
    }
}
