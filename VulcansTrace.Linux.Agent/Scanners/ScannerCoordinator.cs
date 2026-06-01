namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Coordinates concurrent scanner execution and consolidates scanner warnings.
/// </summary>
internal sealed class ScannerCoordinator
{
    private readonly IReadOnlyList<IScanner> _scanners;

    public ScannerCoordinator(IEnumerable<IScanner> scanners)
    {
        _scanners = scanners?.ToList() ?? throw new ArgumentNullException(nameof(scanners));
    }

    public async Task<ScannerRunResult> RunAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var builder = new ScanDataBuilder();
        var warnings = new List<string>();

        var scanTasks = _scanners.Select(s => RunScannerSafelyAsync(s, builder, ct)).ToArray();
        await Task.WhenAll(scanTasks);

        foreach (var task in scanTasks)
        {
            if (task.Result is { Length: > 0 } scannerWarnings)
            {
                warnings.AddRange(scannerWarnings);
            }
        }

        var scanData = builder.Build();
        warnings.AddRange(scanData.Warnings);

        return new ScannerRunResult(scanData, warnings);
    }

    private static async Task<string[]> RunScannerSafelyAsync(
        IScanner scanner,
        ScanDataBuilder builder,
        CancellationToken ct)
    {
        try
        {
            await scanner.ScanAsync(builder, ct);
            return Array.Empty<string>();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new[] { $"Scanner '{scanner.Name}' failed: {ex.Message}" };
        }
    }
}
