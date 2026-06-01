using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class ProcessRunnerTests
{
    [Fact]
    public async Task RunAsync_EchoCommand_CapturesOutput()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("echo hello_world", TimeSpan.FromSeconds(5));

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("hello_world", result.StdOut);
    }

    [Fact]
    public async Task RunAsync_ExitCode1_CapturesStderr()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("echo error_msg >&2; exit 1", TimeSpan.FromSeconds(5));

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("error_msg", result.StdErr);
    }

    [Fact]
    public async Task RunAsync_TimesOut_ReturnsFailure()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("sleep 10", TimeSpan.FromMilliseconds(100));

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("timed out", result.StdErr);
    }

    [Fact]
    public async Task RunAsync_Cancellation_ReturnsFailure()
    {
        var runner = new ProcessRunner();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await runner.RunAsync("echo hello", TimeSpan.FromSeconds(5), cts.Token);

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
    }

    [Fact]
    public async Task RunAsync_EmptyCommand_ReturnsError()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("", TimeSpan.FromSeconds(5));

        Assert.False(result.Success);
        Assert.Contains("empty", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_ZeroTimeout_ReturnsError()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("echo hello", TimeSpan.Zero);

        Assert.False(result.Success);
        Assert.Contains("timeout must be positive", result.StdErr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_NewlineInCommand_DoesNotBreak()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("echo 'line1\nline2'", TimeSpan.FromSeconds(5));

        Assert.True(result.Success);
        Assert.Contains("line1", result.StdOut);
        Assert.Contains("line2", result.StdOut);
    }

    [Fact]
    public async Task RunAsync_PipeInCommand_Works()
    {
        var runner = new ProcessRunner();
        var result = await runner.RunAsync("echo hello | tr a-z A-Z", TimeSpan.FromSeconds(5));

        Assert.True(result.Success);
        Assert.Contains("HELLO", result.StdOut);
    }
}
