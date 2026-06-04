using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class LiveStreamAnalyzerStressTests : IDisposable
{
    private readonly LiveStreamAnalyzer _analyzer;

    public LiveStreamAnalyzerStressTests()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();
        var baseline = new IDetector[] { new PortScanDetector(), new FloodDetector() };
        var linux = Array.Empty<IDetector>();
        var advanced = Array.Empty<IDetector>();
        var riskEscalator = new RiskEscalator();
        var sentry = new SentryAnalyzer(logNormalizer, profileProvider, baseline, linux, advanced, riskEscalator);

        _analyzer = new LiveStreamAnalyzer(
            sentry,
            profileProvider,
            timeWindow: TimeSpan.FromSeconds(5),
            analysisInterval: TimeSpan.FromMilliseconds(100),
            analysisEventThreshold: 10,
            fingerprintTtl: TimeSpan.FromSeconds(2));
    }

    public void Dispose()
    {
        _analyzer.Dispose();
    }

    [Fact]
    public void StopBeforeStart_DoesNotThrow()
    {
        _analyzer.Stop();
        Assert.True(true);
    }

    [Fact]
    public void MultipleStops_DoesNotThrow()
    {
        var source = new SyntheticEventSource(seed: 42);
        _analyzer.Start(source, IntensityLevel.Medium);
        _analyzer.Stop();
        _analyzer.Stop();
        _analyzer.Stop();
        Assert.True(true);
    }

    [Fact]
    public void RapidStartStopCycles_DoesNotThrow()
    {
        for (int i = 0; i < 10; i++)
        {
            var source = new SyntheticEventSource(seed: i);
            _analyzer.Start(source, IntensityLevel.Medium);
            _analyzer.Stop();
        }

        Assert.True(true);
    }

    [Fact]
    public void StartAfterDispose_ThrowsObjectDisposedException()
    {
        var disposableAnalyzer = CreateDisposableAnalyzer();
        disposableAnalyzer.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            disposableAnalyzer.Start(new SyntheticEventSource(), IntensityLevel.Medium));
    }

    [Fact]
    public async Task DisposeWhileRunning_DoesNotDeadlock()
    {
        var source = new SyntheticEventSource(
            new SyntheticPatterns { EventDelayMs = 5 },
            seed: 42);

        _analyzer.Start(source, IntensityLevel.Medium);

        // Let it run briefly
        await Task.Delay(100);

        // Dispose should complete without hanging
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var disposeTask = Task.Run(() => _analyzer.Dispose(), cts.Token);

        var completed = await Task.WhenAny(disposeTask, Task.Delay(TimeSpan.FromSeconds(3), cts.Token));
        Assert.Same(disposeTask, completed);
        Assert.True(disposeTask.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task StopAsync_TimesOutGracefully_WhenPipelineStuck()
    {
        // Use a source that never yields so the pipeline blocks on recv
        var analyzer = CreateDisposableAnalyzer();
        var source = new NeverYieldingEventSource();

        analyzer.Start(source, IntensityLevel.Medium);

        // StopAsync has a 5-second timeout; should return without hanging forever
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var stopTask = analyzer.StopAsync();
        var completed = await Task.WhenAny(stopTask, Task.Delay(TimeSpan.FromSeconds(7), cts.Token));

        Assert.Same(stopTask, completed);
        Assert.True(stopTask.IsCompletedSuccessfully);

        analyzer.Dispose();
    }

    private static LiveStreamAnalyzer CreateDisposableAnalyzer()
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();
        var baseline = new IDetector[] { new PortScanDetector() };
        var riskEscalator = new RiskEscalator();
        var sentry = new SentryAnalyzer(
            logNormalizer, profileProvider, baseline,
            Array.Empty<IDetector>(),
            Array.Empty<IDetector>(),
            riskEscalator);

        return new LiveStreamAnalyzer(
            sentry,
            profileProvider,
            timeWindow: TimeSpan.FromSeconds(2),
            analysisInterval: TimeSpan.FromMilliseconds(50),
            analysisEventThreshold: 5);
    }

    /// <summary>
    /// An event source whose StreamAsync never yields, simulating a blocking
    /// recv() that doesn't return until cancellation/Dispose.
    /// </summary>
    private sealed class NeverYieldingEventSource : IEventSource, IDisposable
    {
        private readonly CancellationTokenSource _cts = new();

        public string DisplayName => "Never Yielding";
        public bool IsAvailable => true;
        public string? UnavailabilityReason => null;

        public async IAsyncEnumerable<UnifiedEvent> StreamAsync(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
            await Task.Delay(Timeout.Infinite, linked.Token).ConfigureAwait(false);
            yield break;
        }

        public void Dispose()
        {
            _cts.Cancel();
            _cts.Dispose();
        }
    }
}
