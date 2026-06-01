using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ScannerCommandRunnerTests
{
    [Fact]
    public async Task RunAsync_TimesOut_ReturnsFailureWithTimeoutMessage()
    {
        var (_, stderr, success) = await ScannerCommandRunner.RunAsync(
            "sh",
            new[] { "-c", "sleep 1" },
            CancellationToken.None,
            TimeSpan.FromMilliseconds(50));

        Assert.False(success);
        Assert.Contains("timed out", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_TruncatesLargeOutput()
    {
        var (stdout, stderr, success) = await ScannerCommandRunner.RunAsync(
            "sh",
            new[] { "-c", "printf 'abcdefghijklmnopqrstuvwxyz'" },
            CancellationToken.None,
            maxOutputChars: 12);

        Assert.True(success);
        Assert.True(stdout?.Length <= 12);
        Assert.Contains("truncated", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => ScannerCommandRunner.RunAsync("sh", new[] { "-c", "echo hello" }, cts.Token));
    }
}
