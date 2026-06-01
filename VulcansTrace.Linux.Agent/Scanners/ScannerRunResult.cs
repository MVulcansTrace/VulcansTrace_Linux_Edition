namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Snapshot produced after running all configured scanners.
/// </summary>
internal sealed record ScannerRunResult(
    ScanData ScanData,
    IReadOnlyList<string> Warnings);
