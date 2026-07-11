using System.Text.Json;
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
    public async Task RunDoctorAsync_SanitizesConsoleAndJsonAndCollapsesWarningFlood()
    {
        using var console = new ConsoleCapture();
        var outputJson = Path.GetTempFileName() + ".json";
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var processError = $"An error occurred trying to start process 'iptables' with working directory '{home}/Projects/private'. No such file or directory";
        var permissionWarnings = Enumerable.Range(0, 40)
            .Select(i => $"find: '/var/{i}': Permission denied")
            .ToArray();

        try
        {
            var result = await Program.RunDoctorAsync(
                ["doctor", "--output-json", outputJson],
                new DoctorService(new[]
                {
                    new CapabilityScanner(
                        "iptables",
                        CapabilityStatus.Unavailable,
                        processError,
                        permissionWarnings,
                        command: $"{home}/bin/iptables --list")
                }));

            Assert.Equal(1, result);
            Assert.Contains("The tool 'iptables' could not be started", console.Output, StringComparison.Ordinal);
            Assert.Contains("40 checks were blocked", console.Output, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("working directory", console.Output, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("find:", console.Output, StringComparison.OrdinalIgnoreCase);
            if (!string.IsNullOrEmpty(home))
                Assert.DoesNotContain(home, console.Output, StringComparison.Ordinal);

            var json = await File.ReadAllTextAsync(outputJson);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var detail = root.GetProperty("capabilities")[0].GetProperty("detail").GetString();
            var warning = root.GetProperty("warnings")[0].GetString();
            Assert.Contains("The tool 'iptables' could not be started", detail, StringComparison.Ordinal);
            Assert.Contains("40 checks were blocked", warning, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("working directory", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("find:", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("/var/", json, StringComparison.Ordinal);
            if (!string.IsNullOrEmpty(home))
                Assert.DoesNotContain(home, json, StringComparison.Ordinal);
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
        private readonly IReadOnlyList<string> _warnings;
        private readonly string? _command;

        public CapabilityScanner(
            string sourceName,
            CapabilityStatus status,
            string? detail = null,
            IReadOnlyList<string>? warnings = null,
            string? command = null)
        {
            _sourceName = sourceName;
            _status = status;
            _detail = detail;
            _warnings = warnings ?? Array.Empty<string>();
            _command = command;
        }

        public string Name => _sourceName;

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = _sourceName,
                Status = _status,
                Detail = _detail,
                Command = _command
            });
            foreach (var warning in _warnings)
                builder.AddWarning(warning);
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
