using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using Xunit;

using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;

namespace VulcansTrace.Linux.Tests.Avalonia;

/// <summary>
/// End-to-end live-stream checks that use the real production wiring from
/// <see cref="AgentFactory"/>. These guard against the situation where the UI
/// shows streaming metrics but the findings grid stays empty.
/// </summary>
[Collection(AvaloniaUiTestCollection.Name)]
public sealed class LiveStreamIntegrationTests : IDisposable
{
    private readonly string _configDir;
    private readonly AgentServices _services;

    public LiveStreamIntegrationTests(ITestOutputHelper output)
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"vt-live-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_configDir);
        _services = AgentFactory.Create(MachineRole.Workstation, _configDir);
        Output = output;
    }

    public ITestOutputHelper Output { get; }

    public void Dispose()
    {
        _services.Dispose();
        try { Directory.Delete(_configDir, true); } catch { }
    }

    [AvaloniaFact]
    public async Task DemoSshBruteforce_AtLowIntensity_ProducesLiveFindings()
    {
        // MainViewModel wires the intensity provider to the global log-analysis
        // intensity, which defaults to Low. Demo scenarios must still produce rows.
        var vm = new LiveStreamViewModel(_services.LiveStreamAnalyzer, () => IntensityLevel.Low);
        vm.SelectedSourceName = "Demo: SSH Brute Force";
        vm.ScenarioDurationSeconds = 30;

        var started = DateTime.UtcNow;
        vm.StartCommand.Execute(null);
        FlushDispatcher();

        Assert.True(vm.IsRunning, "Expected live stream to be running after Start");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            while (vm.LiveFindings.Count == 0 && vm.IsRunning && !cts.Token.IsCancellationRequested)
            {
                FlushDispatcher();
                await Task.Delay(100, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        var elapsed = DateTime.UtcNow - started;
        Output.WriteLine($"SSH brute force (Low provider): Elapsed={elapsed.TotalSeconds:F1}s, LiveFindings={vm.LiveFindings.Count}, " +
                         $"Events/sec={vm.EventsPerSecond:F1}, Window={vm.WindowEventCount}, Runs={vm.AnalysisRunCount}, Delta={vm.TotalDeltaFindings}");

        Assert.True(vm.LiveFindings.Count > 0,
            $"Expected SSH brute-force demo to produce live findings within 20s, but found {vm.LiveFindings.Count}. " +
            $"Metrics after {elapsed.TotalSeconds:F1}s: Events/sec={vm.EventsPerSecond:F1}, Window={vm.WindowEventCount}, Runs={vm.AnalysisRunCount}, Delta={vm.TotalDeltaFindings}");

        vm.StopCommand.Execute(null);
        await ((AsyncRelayCommand)vm.StopCommand).ExecutionTask!;
        FlushDispatcher();
        vm.Dispose();
    }

    [AvaloniaFact]
    public async Task DemoRandomMix_AtLowIntensity_ProducesLiveFindings()
    {
        var vm = new LiveStreamViewModel(_services.LiveStreamAnalyzer, () => IntensityLevel.Low);
        vm.SelectedSourceName = "Demo: Random Mix";
        vm.ScenarioDurationSeconds = 30;

        var started = DateTime.UtcNow;
        vm.StartCommand.Execute(null);
        FlushDispatcher();

        Assert.True(vm.IsRunning);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            while (vm.LiveFindings.Count == 0 && vm.IsRunning && !cts.Token.IsCancellationRequested)
            {
                FlushDispatcher();
                await Task.Delay(100, cts.Token);
            }
        }
        catch (OperationCanceledException) { }

        var elapsed = DateTime.UtcNow - started;
        Output.WriteLine($"Random mix (Low provider): Elapsed={elapsed.TotalSeconds:F1}s, LiveFindings={vm.LiveFindings.Count}, " +
                         $"Events/sec={vm.EventsPerSecond:F1}, Window={vm.WindowEventCount}, Runs={vm.AnalysisRunCount}, Delta={vm.TotalDeltaFindings}");

        Assert.True(vm.LiveFindings.Count > 0,
            $"Expected random-mix demo at Low intensity to produce findings, but found {vm.LiveFindings.Count} after {elapsed.TotalSeconds:F1}s.");

        vm.StopCommand.Execute(null);
        await ((AsyncRelayCommand)vm.StopCommand).ExecutionTask!;
        FlushDispatcher();
        vm.Dispose();
    }

}
