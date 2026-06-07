using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Agent.Diagnostics;

/// <summary>
/// Self-diagnostic service that probes all scanners and reports data-source
/// capability/visibility without running rule evaluation or log analysis.
/// </summary>
public sealed class DoctorService
{
    private readonly IReadOnlyList<IScanner> _scanners;

    /// <summary>
    /// Initializes a new instance of the <see cref="DoctorService"/> class.
    /// </summary>
    /// <param name="scanners">The scanners to probe for capability information.</param>
    public DoctorService(IEnumerable<IScanner> scanners)
    {
        _scanners = scanners?.ToList() ?? throw new ArgumentNullException(nameof(scanners));
    }

    /// <summary>
    /// Runs a lightweight probe across all scanners and returns capability visibility.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the probe.</param>
    /// <returns>A <see cref="DoctorResult"/> summarizing data-source health.</returns>
    public async Task<DoctorResult> ProbeAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var coordinator = new ScannerCoordinator(_scanners);
        var runResult = await coordinator.RunAsync(cancellationToken);
        var scanData = runResult.ScanData;

        var composer = new AgentResultComposer();
        var capabilities = composer.NormalizeCapabilities(scanData.Capabilities);
        var capabilityReport = composer.BuildCapabilityReport(capabilities);

        var permissionLimited = capabilities.Count(c => c.Status == CapabilityStatus.PermissionLimited);
        var unavailable = capabilities.Count(c => c.Status == CapabilityStatus.Unavailable);
        var unknown = capabilities.Count(c => c.Status == CapabilityStatus.Unknown);
        var isHealthy = capabilities.Count > 0 && capabilities.All(c => c.Status == CapabilityStatus.Available);

        return new DoctorResult
        {
            Capabilities = capabilities,
            CapabilityReport = capabilityReport,
            IsHealthy = isHealthy,
            PermissionLimitedCount = permissionLimited,
            UnavailableCount = unavailable,
            UnknownCount = unknown,
            Warnings = runResult.Warnings.ToArray()
        };
    }
}
