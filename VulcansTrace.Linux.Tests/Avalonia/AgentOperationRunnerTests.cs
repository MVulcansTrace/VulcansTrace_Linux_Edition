using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;

using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class AgentOperationRunnerTests
{
    [AvaloniaFact]
    public async Task RunAsync_SetsBusyTrueThenFalse()
    {
        var busyStates = new List<bool>();
        var runner = CreateRunner(setBusy: v => busyStates.Add(v));

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.Equal(new[] { true, false }, busyStates);
    }

    [AvaloniaFact]
    public async Task RunAsync_ClearsPrivilegeWarningBeforeRunning()
    {
        var clearCount = 0;
        var runner = CreateRunner(clearPrivilegeWarning: () => clearCount++);

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.Equal(1, clearCount);
    }

    [AvaloniaFact]
    public async Task RunAsync_Success_CompletesAndCanCancelIsFalse()
    {
        var runner = CreateRunner();

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.False(runner.CanCancel);
    }

    [AvaloniaFact]
    public async Task RunAsync_OperationCanceledException_PostsCancelledMessage()
    {
        var messages = new ObservableCollection<(string Text, bool IsInfo, bool IsError)>();
        var runner = CreateRunner(addAgentMessage: (text, isInfo, isError) => messages.Add((text, isInfo, isError)));

        await runner.RunAsync(_ => throw new OperationCanceledException());
        FlushDispatcher();

        Assert.Contains(messages, m => m.Text == "Query cancelled." && m.IsInfo && !m.IsError);
    }

    [AvaloniaFact]
    public async Task RunAsync_GenericException_PostsAgentErrorMessage()
    {
        var messages = new ObservableCollection<(string Text, bool IsInfo, bool IsError)>();
        var runner = CreateRunner(addAgentMessage: (text, isInfo, isError) => messages.Add((text, isInfo, isError)));

        await runner.RunAsync(_ => throw new InvalidOperationException("something broke"));
        FlushDispatcher();

        Assert.Contains(messages, m => m.Text == "Agent error: something broke" && m.IsInfo && m.IsError);
    }

    [AvaloniaFact]
    public async Task RunAsync_ExceptionStillClearsBusy()
    {
        var busyStates = new List<bool>();
        var runner = CreateRunner(setBusy: v => busyStates.Add(v));

        await runner.RunAsync(_ => throw new InvalidOperationException("fail"));
        FlushDispatcher();

        Assert.Equal(new[] { true, false }, busyStates);
    }

    [AvaloniaFact]
    public async Task LastSucceeded_True_WhenOperationCompletes()
    {
        var runner = CreateRunner();

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.True(runner.LastSucceeded);
    }

    [AvaloniaFact]
    public async Task LastSucceeded_False_WhenOperationThrows()
    {
        var runner = CreateRunner();

        await runner.RunAsync(_ => throw new InvalidOperationException("boom"));
        FlushDispatcher();

        Assert.False(runner.LastSucceeded);
        Assert.True(runner.LastFailed);
    }

    [AvaloniaFact]
    public async Task LastSucceeded_False_WhenOperationCancelled()
    {
        var runner = CreateRunner();
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var runTask = runner.RunAsync(async ct =>
        {
            started.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        });

        await started.Task;
        runner.Cancel();
        await runTask;
        FlushDispatcher();

        Assert.False(runner.LastSucceeded);
        Assert.False(runner.LastFailed);
    }

    [AvaloniaFact]
    public async Task LastFailed_ResetsAfterLaterSuccess()
    {
        var runner = CreateRunner();

        await runner.RunAsync(_ => throw new InvalidOperationException("boom"));
        FlushDispatcher();
        Assert.True(runner.LastFailed);

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.False(runner.LastFailed);
    }

    [AvaloniaFact]
    public void CanCancel_FalseWhenNoOperationRunning()
    {
        var runner = CreateRunner();

        Assert.False(runner.CanCancel);
    }

    [AvaloniaFact]
    public async Task Cancel_TriggersOperationCanceledException()
    {
        var messages = new ObservableCollection<(string Text, bool IsInfo, bool IsError)>();
        var runner = CreateRunner(addAgentMessage: (text, isInfo, isError) => messages.Add((text, isInfo, isError)));

        // Wait until the operation has actually started before cancelling, so the test doesn't race
        // on async-lambda setup timing (which made CanCancel flicker under concurrent load).
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var runTask = runner.RunAsync(async ct =>
        {
            started.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        });

        await started.Task;
        Assert.True(runner.CanCancel);

        runner.Cancel();
        await runTask;

        // The cancellation continuation posts "Query cancelled." to the dispatcher from a thread-pool
        // thread, so pump the dispatcher until the message is drained rather than assuming a single
        // pass suffices under load.
        await WaitForAsync(() => messages.Any(m => m.Text == "Query cancelled." && m.IsInfo));

        Assert.False(runner.CanCancel);
        Assert.Contains(messages, m => m.Text == "Query cancelled." && m.IsInfo && !m.IsError);
    }

    [AvaloniaFact]
    public async Task RunAsync_SecondRunDisposesPreviousCancellationTokenSource()
    {
        var runner = CreateRunner();
        var firstRunCompleted = false;

        var firstTask = runner.RunAsync(async ct =>
        {
            await Task.Delay(50, ct);
            firstRunCompleted = true;
        });

        await firstTask;
        FlushDispatcher();

        Assert.True(firstRunCompleted);

        await runner.RunAsync(_ => Task.CompletedTask);
        FlushDispatcher();

        Assert.False(runner.CanCancel);
    }

    [AvaloniaFact]
    public async Task Dispose_CancelsActiveOperation()
    {
        var runner = CreateRunner();
        var runTask = runner.RunAsync(async ct =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        });

        runner.Dispose();
        await runTask;
        FlushDispatcher();

        Assert.False(runner.CanCancel);
    }

    [AvaloniaFact]
    public void Dispose_WhenNoOperationRunning_DoesNotThrow()
    {
        var runner = CreateRunner();

        runner.Dispose();
    }

    [AvaloniaFact]
    public async Task RunAsync_NullOperation_ThrowsArgumentNullException()
    {
        var runner = CreateRunner();

        await Assert.ThrowsAsync<ArgumentNullException>(() => runner.RunAsync((Func<CancellationToken, Task>)null!));
    }

    [AvaloniaFact]
    public void Constructor_NullSetBusy_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AgentOperationRunner(null!, () => { }, (text, isInfo, isError) => { }));
    }

    [AvaloniaFact]
    public void Constructor_NullClearPrivilegeWarning_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AgentOperationRunner(_ => { }, null!, (text, isInfo, isError) => { }));
    }

    [AvaloniaFact]
    public void Constructor_NullAddAgentMessage_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AgentOperationRunner(_ => { }, () => { }, null!));
    }

    [AvaloniaFact]
    public async Task RunAsync_ProgressOverload_ReportsProgressOnUiThread()
    {
        var progressReports = new List<AgentAuditProgress>();
        var runner = new AgentOperationRunner(
            _ => { },
            () => { },
            (_, _, _) => { },
            p => progressReports.Add(p));

        await runner.RunAsync((progress, ct) =>
        {
            progress?.Report(new AgentAuditProgress
            {
                Phase = "Test phase",
                StepIndex = 0,
                TotalSteps = 2
            });
            return Task.CompletedTask;
        });
        FlushDispatcher();

        var report = Assert.Single(progressReports);
        Assert.Equal("Test phase", report.Phase);
        Assert.Equal(0, report.StepIndex);
        Assert.Equal(2, report.TotalSteps);
    }

    /// <summary>Pumps the dispatcher until <paramref name="condition" /> holds, or the timeout lapses.</summary>
    private static async Task WaitForAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (!condition() && Environment.TickCount64 < deadline)
        {
            FlushDispatcher();
            await Task.Delay(10);
        }
    }

    private static AgentOperationRunner CreateRunner(
        Action<bool>? setBusy = null,
        Action? clearPrivilegeWarning = null,
        Action<string, bool, bool>? addAgentMessage = null)
    {
        return new AgentOperationRunner(
            setBusy ?? (_ => { }),
            clearPrivilegeWarning ?? (() => { }),
            addAgentMessage ?? ((_, _, _) => { }));
    }
}
