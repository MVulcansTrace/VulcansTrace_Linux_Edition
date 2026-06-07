using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Cli;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class DoctorCommandTests
{
    [Fact]
    public async Task RunDoctorAsync_AllAvailable_ReturnsZero()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunDoctorAsync(["doctor"], new DoctorService(new[]
        {
            new CapabilityScanner("iptables", CapabilityStatus.Available),
            new CapabilityScanner("ss", CapabilityStatus.Available)
        }));

        Assert.Equal(0, result);
        Assert.Contains("All data sources are available.", console.Output);
    }

    [Fact]
    public async Task RunDoctorAsync_Unavailable_ReturnsOne()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunDoctorAsync(["doctor"], new DoctorService(new[]
        {
            new CapabilityScanner("iptables", CapabilityStatus.Available),
            new CapabilityScanner("docker ps", CapabilityStatus.Unavailable, "command not found")
        }));

        Assert.Equal(1, result);
        Assert.Contains("1 unavailable", console.Output);
    }

    [Fact]
    public async Task RunDoctorAsync_PermissionLimitedOnly_ReturnsTwo()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunDoctorAsync(["doctor"], new DoctorService(new[]
        {
            new CapabilityScanner("shadow", CapabilityStatus.PermissionLimited, "Permission denied")
        }));

        Assert.Equal(2, result);
        Assert.Contains("1 permission-limited", console.Output);
    }

    [Fact]
    public async Task RunDoctorAsync_UnknownOnly_ReturnsTwo()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunDoctorAsync(["doctor"], new DoctorService(new[]
        {
            new CapabilityScanner("file-hash", CapabilityStatus.Unknown, "Skipped because no imported file-hash IOCs are loaded.")
        }));

        Assert.Equal(2, result);
        Assert.Contains("1 not checked", console.Output);
        Assert.DoesNotContain("All data sources are available.", console.Output);
    }

    [Fact]
    public async Task RunDoctorAsync_WritesJsonOutput_WithStringStatuses()
    {
        using var console = new ConsoleCapture();
        var outputJson = Path.GetTempFileName() + ".json";
        try
        {
            var result = await Program.RunDoctorAsync(["doctor", "--output-json", outputJson], new DoctorService(new[]
            {
                new CapabilityScanner("iptables", CapabilityStatus.Available)
            }));

            Assert.Equal(0, result);
            var content = await File.ReadAllTextAsync(outputJson);
            Assert.Contains("\"capabilities\"", content);
            Assert.Contains("\"status\": \"Available\"", content);
            Assert.Contains("\"capabilityReport\"", content);
        }
        finally
        {
            if (File.Exists(outputJson)) File.Delete(outputJson);
        }
    }

    [Fact]
    public async Task RunDoctorAsync_OutputJsonDirectory_ReturnsErrorBeforeProbe()
    {
        using var console = new ConsoleCapture();
        var scanner = new CountingScanner();
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var result = await Program.RunDoctorAsync(["doctor", "--output-json", tempDir], new DoctorService(new[] { scanner }));

            Assert.Equal(1, result);
            Assert.Equal(0, scanner.RunCount);
        }
        finally
        {
            Directory.Delete(tempDir);
        }
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

    private sealed class CountingScanner : IScanner
    {
        public int RunCount { get; private set; }

        public string Name => "Counting";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            RunCount++;
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "iptables",
                Status = CapabilityStatus.Available
            });
            return Task.CompletedTask;
        }
    }

    private sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter _originalOut = Console.Out;
        private readonly StringWriter _writer = new();

        public ConsoleCapture()
        {
            Console.SetOut(_writer);
        }

        public string Output => _writer.ToString();

        public void Dispose()
        {
            Console.SetOut(_originalOut);
            _writer.Dispose();
        }
    }
}
