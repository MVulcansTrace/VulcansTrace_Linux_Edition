using System.Reflection;
using System.Threading;
using Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Tests.Avalonia;

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

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
    public void StartCommand_CanExecute_WhenNotRunningAndSourceAvailable()
    {
        var vm = CreateViewModel();
        vm.SelectedSourceName = "Demo: Random Mix";

        Assert.True(vm.StartCommand.CanExecute(null));
        Assert.False(vm.StopCommand.CanExecute(null));
    }

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var vm = CreateViewModel();
        vm.Dispose();
        Assert.True(true);
    }

    [Fact]
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

    [Fact]
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

    [Fact]
    public void IsScenarioSource_False_ForKernelSources()
    {
        var vm = CreateViewModel();

        vm.SelectedSourceName = "Kernel Packet Capture (AF_PACKET + BPF)";
        Assert.False(vm.IsScenarioSource);

        vm.SelectedSourceName = "NFLOG Netlink (AF_NETLINK)";
        Assert.False(vm.IsScenarioSource);
    }

    [Fact]
    public void SelectedSourceName_RaisesIsScenarioSourceChanged()
    {
        var vm = CreateViewModel();
        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        vm.SelectedSourceName = "Kernel Packet Capture (AF_PACKET + BPF)";

        Assert.Contains(nameof(LiveStreamViewModel.IsScenarioSource), changed);
    }

    [Fact]
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

    [Fact]
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

    private static void FlushDispatcher() => Dispatcher.UIThread.RunJobs();
}
