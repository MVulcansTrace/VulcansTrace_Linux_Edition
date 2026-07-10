using System.Diagnostics;
using System.Reflection;
using System.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;

using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class LiveStreamViewModelTests : IDisposable
{
    private readonly LiveStreamAnalyzer _analyzer;

    public LiveStreamViewModelTests()
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
            timeWindow: TimeSpan.FromSeconds(10),
            analysisInterval: TimeSpan.FromMilliseconds(100),
            analysisEventThreshold: 20,
            fingerprintTtl: TimeSpan.FromSeconds(5));
    }

    public void Dispose()
    {
        _analyzer.Dispose();
    }

    private LiveStreamViewModel CreateViewModel()
    {
        return new LiveStreamViewModel(_analyzer);
    }

    [AvaloniaFact]
    public void Constructor_InitializesDefaultState()
    {
        var vm = CreateViewModel();

        Assert.False(vm.IsRunning);
        Assert.Equal("Stopped", vm.StatusText);
        Assert.Empty(vm.LiveFindings);
        Assert.Equal(0, vm.TotalDeltaFindings);
        Assert.Equal(0, vm.EventsPerSecond);
        Assert.Equal(0, vm.WindowEventCount);
    }

    [AvaloniaFact]
    public void AvailableSources_ContainsExpectedNames()
    {
        var vm = CreateViewModel();

        Assert.Equal(6, vm.AvailableSources.Count);
        Assert.Contains("Demo: Random Mix", vm.AvailableSources);
        Assert.Contains("Demo: C2 Beaconing", vm.AvailableSources);
        Assert.Contains("Demo: SSH Brute Force", vm.AvailableSources);
        Assert.Contains("Demo: Privilege Escalation", vm.AvailableSources);
        Assert.Contains("Kernel Packet Capture (AF_PACKET + BPF)", vm.AvailableSources);
        Assert.Contains("NFLOG Netlink (AF_NETLINK)", vm.AvailableSources);
    }

    private static IEventSource InvokeResolveSource(LiveStreamViewModel vm)
    {
        var method = typeof(LiveStreamViewModel).GetMethod(
            "ResolveSource",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        return (IEventSource)method.Invoke(vm, null)!;
    }

    [AvaloniaFact]
    public void ResolveSource_ReturnsCorrectTypes()
    {
        var vm = CreateViewModel();

        vm.SelectedSourceName = "Demo: Random Mix";
        Assert.IsType<SyntheticEventSource>(InvokeResolveSource(vm));

        vm.SelectedSourceName = "Demo: C2 Beaconing";
        Assert.IsType<SyntheticEventSource>(InvokeResolveSource(vm));

        vm.SelectedSourceName = "Demo: SSH Brute Force";
        Assert.IsType<SyntheticEventSource>(InvokeResolveSource(vm));

        vm.SelectedSourceName = "Demo: Privilege Escalation";
        Assert.IsType<SyntheticEventSource>(InvokeResolveSource(vm));

        vm.SelectedSourceName = "Kernel Packet Capture (AF_PACKET + BPF)";
        Assert.IsType<PacketCaptureEventSource>(InvokeResolveSource(vm));

        vm.SelectedSourceName = "NFLOG Netlink (AF_NETLINK)";
        Assert.IsType<NflogEventSource>(InvokeResolveSource(vm));
    }

    [AvaloniaFact]
    public void ResolveSource_UnknownName_Throws()
    {
        var vm = CreateViewModel();
        // Set the backing field directly to bypass the setter (which calls ResolveSource)
        var field = typeof(LiveStreamViewModel).GetField(
            "_selectedSourceName",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        field.SetValue(vm, "Nonexistent Source");

        var ex = Assert.Throws<TargetInvocationException>(() => InvokeResolveSource(vm));
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }

    [AvaloniaFact]
    public void StartCommand_CanExecute_WhenNotRunningAndSourceAvailable()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";

        Assert.True(vm.StartCommand.CanExecute(null));
        Assert.False(vm.StopCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void StopCommand_CanExecute_WhenRunning()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";

        vm.StartCommand.Execute(null);

        Assert.False(vm.StartCommand.CanExecute(null));
        Assert.True(vm.StopCommand.CanExecute(null));

        // Cleanup
        vm.StopCommand.Execute(null);
        FlushDispatcher();
    }

    [AvaloniaFact]
    public async Task Start_SetsIsRunningAndStatusText()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        Assert.True(vm.IsRunning);
        Assert.Contains("Capturing", vm.StatusText);

        // Cleanup — await the async stop command
        vm.StopCommand.Execute(null);
        await ((AsyncRelayCommand)vm.StopCommand).ExecutionTask!;
        FlushDispatcher();
    }

    [AvaloniaFact]
    public async Task Stop_ClearsIsRunningAndStatusText()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        vm.StopCommand.Execute(null);
        await ((AsyncRelayCommand)vm.StopCommand).ExecutionTask!;
        FlushDispatcher();

        Assert.False(vm.IsRunning);
        Assert.Contains("complete", vm.StatusText, StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public void Dispose_DoesNotThrow()
    {
        var vm = CreateViewModel();
        vm.Dispose();
        Assert.True(true);
    }

    [AvaloniaFact]
    public async Task Dispose_WhileRunning_DoesNotThrowAndStops()
    {
        // A demo still running when Dispose() is called must tear down the auto-stop
        // background task and its CTS without throwing and leave the VM stopped.
        // Regression guard for the orphaned-auto-stop teardown gap.
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 60; // long enough to guarantee we dispose mid-run

        vm.StartCommand.Execute(null);
        FlushDispatcher();
        Assert.True(vm.IsRunning, "Stream should be running after Start");

        // Let the auto-stop Task.Run enter its delay, then dispose while running.
        await Task.Delay(150);
        FlushDispatcher();
        Assert.True(vm.IsRunning, "Stream should still be running before dispose");

        vm.Dispose(); // must not throw with the auto-stop task in flight

        Assert.False(vm.IsRunning, "Dispose must leave IsRunning false");

        // The task owns disposal and must promptly clear its published CTS after
        // observing cancellation; otherwise Dispose merely hides an orphaned task.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (GetAutoStopCts(vm) is not null && !timeout.IsCancellationRequested)
        {
            await Task.Delay(20);
        }
        Assert.Null(GetAutoStopCts(vm));
    }

    [AvaloniaFact]
    public async Task Dispose_WhileAutoStopInFlight_DoesNotBlockTheUIThread()
    {
        // Regression guard for the UI-thread freeze. The auto-stop background task
        // ends StopAsync with `await UiThread.InvokeAsync(applyStopState)`, which can
        // only complete on the UI thread. A Dispose that blocked waiting for that task
        // would deadlock the final hop and freeze the close for the wait's full timeout.
        //
        // We park the task in exactly that state: start a 1s demo, then Sleep on the UI
        // thread (without pumping) past the 1s auto-stop. The task runs StopAsync on the
        // threadpool, reaches its InvokeAsync tail, and parks with applyStopState queued.
        // Dispose must return promptly rather than block on the parked task.
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 1;

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        Thread.Sleep(1500); // let the 1s auto-stop elapse and park at InvokeAsync

        var sw = Stopwatch.StartNew();
        vm.Dispose();
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 1000,
            $"Dispose blocked the UI thread for {sw.ElapsedMilliseconds}ms (expected sub-second).");
        Assert.False(vm.IsRunning);

        // Let the parked tail drain on the dispatcher before teardown disposes the analyzer.
        await Task.Delay(100);
        FlushDispatcher();
    }

    [AvaloniaFact]
    public async Task LiveResultReceived_RaisedWhenResultsArrive()
    {
        var vm = CreateViewModel();
        var received = new List<LiveAnalysisResult>();
        vm.LiveResultReceived += (_, result) => received.Add(result);

        vm.SelectedSourceName = "Demo: Random Mix";
        vm.StartCommand.Execute(null);
        FlushDispatcher();

        // Give the fast synthetic source time to produce at least one result
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            while (received.Count == 0 && !cts.Token.IsCancellationRequested)
            {
                FlushDispatcher();
                await Task.Delay(50, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        vm.StopCommand.Execute(null);
        FlushDispatcher();
        vm.Dispose();

        Assert.True(received.Count >= 1, "Should receive at least one live result event");
    }

    [AvaloniaFact]
    public void IsScenarioSource_True_ForDemoScenarios()
    {
        var vm = CreateViewModel();

        vm.SelectedSourceName = "Demo: Random Mix";
        Assert.True(vm.IsScenarioSource);

        vm.SelectedSourceName = "Demo: C2 Beaconing";
        Assert.True(vm.IsScenarioSource);

        vm.SelectedSourceName = "Demo: SSH Brute Force";
        Assert.True(vm.IsScenarioSource);

        vm.SelectedSourceName = "Demo: Privilege Escalation";
        Assert.True(vm.IsScenarioSource);
    }

    [AvaloniaFact]
    public void IsScenarioSource_False_ForKernelSources()
    {
        var vm = CreateViewModel();

        vm.SelectedSourceName = "Kernel Packet Capture (AF_PACKET + BPF)";
        Assert.False(vm.IsScenarioSource);

        vm.SelectedSourceName = "NFLOG Netlink (AF_NETLINK)";
        Assert.False(vm.IsScenarioSource);
    }

    [AvaloniaFact]
    public void SelectedSourceName_RaisesIsScenarioSourceChanged()
    {
        var vm = CreateViewModel();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.SelectedSourceName = "Kernel Packet Capture (AF_PACKET + BPF)";

        Assert.Contains(nameof(LiveStreamViewModel.IsScenarioSource), changed);
    }

    [AvaloniaFact]
    public async Task ScenarioAutoStop_StopsAfterDuration()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 2;

        var completed = new List<DemoCompletedEventArgs>();
        vm.DemoCompleted += (_, e) => completed.Add(e);

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        Assert.True(vm.IsRunning);

        // Wait for auto-stop
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (vm.IsRunning && !cts.Token.IsCancellationRequested)
            {
                FlushDispatcher();
                await Task.Delay(50, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        FlushDispatcher();

        // Allow the auto-stop background task to finish raising the event
        await Task.Delay(300);

        vm.Dispose();

        Assert.False(vm.IsRunning, "Should have stopped after 2 seconds");
        Assert.Single(completed);
        Assert.True(completed[0].WasAutoStop);
        Assert.Equal("Demo: Random Mix", completed[0].ScenarioName);
        Assert.Equal(completed[0].Findings.Count, completed[0].TotalFindings);
    }

    [AvaloniaFact]
    public async Task StopState_IsRaisedOnUiThread_Diagnostic()
    {
        // Diagnoses the Live Stream end/stop desync: the stream stops and the
        // ViewModel values change, but if those changes are raised off the UI
        // thread the banner/dot bindings never re-render while the command-based
        // buttons do. This captures which thread raised the stop transition.
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 2;

        var uiThreadId = Environment.CurrentManagedThreadId;

        int? isRunningStopThreadId = null;
        int? statusStopThreadId = null;
        string? observedStatus = null;

        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(LiveStreamViewModel.IsRunning) && !vm.IsRunning)
            {
                isRunningStopThreadId ??= Environment.CurrentManagedThreadId;
            }
            if (e.PropertyName == nameof(LiveStreamViewModel.StatusText)
                && vm.StatusText.Contains("complete", StringComparison.OrdinalIgnoreCase))
            {
                statusStopThreadId ??= Environment.CurrentManagedThreadId;
                observedStatus ??= vm.StatusText;
            }
        };

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        try
        {
            while (vm.IsRunning && !cts.Token.IsCancellationRequested)
            {
                FlushDispatcher();
                await Task.Delay(50, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        // Allow the auto-stop background task to finish raising events.
        await Task.Delay(300);
        FlushDispatcher();
        vm.Dispose();

        Assert.True(isRunningStopThreadId.HasValue,
            "IsRunning never transitioned to false (auto-stop did not run).");
        Assert.True(statusStopThreadId.HasValue,
            "StatusText never reached a 'complete' value (auto-stop did not run).");

        Assert.True(isRunningStopThreadId.Value == uiThreadId,
            $"IsRunning=false was raised OFF the UI thread " +
            $"(raising thread {isRunningStopThreadId.Value}, UI thread {uiThreadId}).");

        Assert.True(statusStopThreadId.Value == uiThreadId,
            $"StatusText stop value ('{observedStatus}') was raised OFF the UI thread " +
            $"(raising thread {statusStopThreadId.Value}, UI thread {uiThreadId}).");
    }

    [AvaloniaFact]
    public async Task DemoCompleted_RaisedOnManualStop()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 10;

        var completed = new List<DemoCompletedEventArgs>();
        vm.DemoCompleted += (_, e) => completed.Add(e);

        vm.StartCommand.Execute(null);
        FlushDispatcher();

        // Stop manually before timer fires
        vm.StopCommand.Execute(null);
        await ((AsyncRelayCommand)vm.StopCommand).ExecutionTask!;
        FlushDispatcher();
        vm.Dispose();

        Assert.Single(completed);
        Assert.False(completed[0].WasAutoStop);
        Assert.Equal(completed[0].Findings.Count, completed[0].TotalFindings);
    }

    private static CancellationTokenSource? GetAutoStopCts(LiveStreamViewModel vm) =>
        (CancellationTokenSource?)typeof(LiveStreamViewModel)
            .GetField("_autoStopCts", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(vm);

}
