using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class DoctorServiceTests
{
    [Fact]
    public async Task ProbeAsync_ReturnsCapabilities_FromScanners()
    {
        var service = new DoctorService(new IScanner[]
        {
            new CapabilityScanner("iptables", CapabilityStatus.Available),
            new CapabilityScanner("ss", CapabilityStatus.PermissionLimited, "Permission denied")
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.Equal(2, result.Capabilities.Count);
        Assert.Contains(result.Capabilities, c => c.SourceName == "iptables" && c.Status == CapabilityStatus.Available);
        Assert.Contains(result.Capabilities, c => c.SourceName == "ss" && c.Status == CapabilityStatus.PermissionLimited);
        Assert.False(result.IsHealthy);
        Assert.Equal(1, result.PermissionLimitedCount);
        Assert.Equal(0, result.UnavailableCount);
        Assert.Equal(0, result.UnknownCount);
    }

    [Fact]
    public async Task ProbeAsync_HandlesScannerExceptions_Gracefully()
    {
        var service = new DoctorService(new IScanner[]
        {
            new ThrowingScanner(),
            new CapabilityScanner("iptables", CapabilityStatus.Available)
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.Single(result.Capabilities);
        Assert.Contains(result.Capabilities, c => c.SourceName == "iptables");
        Assert.Contains(result.Warnings, w => w.Contains("Scanner 'Throwing' failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ProbeAsync_ReportsHealthy_WhenAllAvailable()
    {
        var service = new DoctorService(new IScanner[]
        {
            new CapabilityScanner("iptables", CapabilityStatus.Available),
            new CapabilityScanner("ss", CapabilityStatus.Available)
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.True(result.IsHealthy);
        Assert.Equal(0, result.PermissionLimitedCount);
        Assert.Equal(0, result.UnavailableCount);
        Assert.Equal(0, result.UnknownCount);
        Assert.NotEmpty(result.CapabilityReport);
    }

    [Fact]
    public async Task ProbeAsync_ReportsNotHealthy_WhenUnavailable()
    {
        var service = new DoctorService(new IScanner[]
        {
            new CapabilityScanner("docker", CapabilityStatus.Unavailable, "command not found")
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.False(result.IsHealthy);
        Assert.Equal(0, result.PermissionLimitedCount);
        Assert.Equal(1, result.UnavailableCount);
        Assert.Equal(0, result.UnknownCount);
    }

    [Fact]
    public async Task ProbeAsync_ReportsNotHealthy_WhenUnknown()
    {
        var service = new DoctorService(new IScanner[]
        {
            new CapabilityScanner("file-hash", CapabilityStatus.Unknown, "Skipped because no imported file-hash IOCs are loaded.")
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.False(result.IsHealthy);
        Assert.Equal(0, result.PermissionLimitedCount);
        Assert.Equal(0, result.UnavailableCount);
        Assert.Equal(1, result.UnknownCount);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsDeterministicDeduplicatedCapabilities()
    {
        var service = new DoctorService(new IScanner[]
        {
            new CapabilityScanner("systemctl", CapabilityStatus.Unavailable),
            new CapabilityScanner("iptables", CapabilityStatus.Available),
            new CapabilityScanner("systemctl", CapabilityStatus.PermissionLimited, "Permission denied"),
            new CapabilityScanner("ss", CapabilityStatus.Available)
        });

        var result = await service.ProbeAsync(CancellationToken.None);

        Assert.Collection(
            result.Capabilities,
            cap => Assert.Equal("iptables", cap.SourceName),
            cap => Assert.Equal("ss", cap.SourceName),
            cap =>
            {
                Assert.Equal("systemctl", cap.SourceName);
                Assert.Equal(CapabilityStatus.PermissionLimited, cap.Status);
            });
        Assert.Equal("Data sources: iptables available; ss available; systemctl permission-limited (Permission denied).", result.CapabilityReport);
    }

    [Fact]
    public async Task ProbeAsync_Cancellation_Throws()
    {
        var service = new DoctorService(new IScanner[] { new CapabilityScanner("iptables", CapabilityStatus.Available) });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => service.ProbeAsync(cts.Token));
    }

    private sealed class CapabilityScanner : IScanner
    {
        private readonly string _sourceName;
        private readonly CapabilityStatus _status;
        private readonly string? _detail;

        public CapabilityScanner(string sourceName, CapabilityStatus status, string? detail = null)
        {
            _sourceName = sourceName;
            _status = status;
            _detail = detail;
        }

        public string Name => _sourceName;

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = _sourceName,
                Status = _status,
                Detail = _detail
            });
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
