using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class ScannerCoordinatorTests
{
    [Fact]
    public async Task RunAsync_CollectsBuilderWarnings()
    {
        var coordinator = new ScannerCoordinator(new IScanner[] { new WarningScanner("scanner warning") });

        var result = await coordinator.RunAsync(CancellationToken.None);

        Assert.Contains("scanner warning", result.Warnings);
    }

    [Fact]
    public async Task RunAsync_ScannerFailure_ReturnsWarningAndContinues()
    {
        var coordinator = new ScannerCoordinator(new IScanner[]
        {
            new ThrowingScanner(),
            new WarningScanner("second scanner still ran")
        });

        var result = await coordinator.RunAsync(CancellationToken.None);

        Assert.Contains(result.Warnings, w => w.Contains("Scanner 'Throwing' failed", StringComparison.Ordinal));
        Assert.Contains("second scanner still ran", result.Warnings);
    }

    [Fact]
    public async Task RunAsync_Cancellation_Throws()
    {
        var coordinator = new ScannerCoordinator(new IScanner[] { new WarningScanner("unused") });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => coordinator.RunAsync(cts.Token));
    }

    private sealed class WarningScanner(string warning) : IScanner
    {
        public string Name => "Warning";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            builder.AddWarning(warning);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingScanner : IScanner
    {
        public string Name => "Throwing";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("boom");
        }
    }
}
