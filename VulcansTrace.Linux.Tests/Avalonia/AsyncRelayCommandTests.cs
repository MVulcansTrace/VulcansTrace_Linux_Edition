using System;
using System.Threading.Tasks;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AsyncRelayCommandTests
{
    [Fact]
    public void Execute_SynchronousThrow_CallsExceptionHandlerAndResetsExecuting()
    {
        Exception? captured = null;
        var expected = new InvalidOperationException("boom");

        var cmd = new AsyncRelayCommand(
            execute: _ => throw expected,
            canExecute: _ => true,
            onException: ex => captured = ex);

        Assert.True(cmd.CanExecute(null));

        cmd.Execute(null);

        Assert.Same(expected, captured);
        Assert.True(cmd.CanExecute(null)); // _isExecuting was reset
    }

    [Fact]
    public async Task Execute_AsyncThrow_CallsExceptionHandlerAndResetsExecuting()
    {
        Exception? captured = null;
        var expected = new InvalidOperationException("async boom");

        var cmd = new AsyncRelayCommand(
            execute: async _ =>
            {
                await Task.Yield();
                throw expected;
            },
            canExecute: _ => true,
            onException: ex => captured = ex);

        cmd.Execute(null);
        await cmd.ExecutionTask;

        Assert.Same(expected, captured);
        Assert.True(cmd.CanExecute(null));
    }

    [Fact]
    public void Execute_WhileExecuting_SecondCallIgnored()
    {
        var tcs = new TaskCompletionSource();
        var executeCount = 0;

        var cmd = new AsyncRelayCommand(
            execute: async _ =>
            {
                executeCount++;
                await tcs.Task;
            },
            canExecute: _ => true);

        cmd.Execute(null);
        Assert.False(cmd.CanExecute(null));

        cmd.Execute(null); // should be ignored
        Assert.Equal(1, executeCount);

        tcs.SetResult();
    }
}
