using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Tests.Agent.Scanners;

public class YaraScannerTests
{
    [Fact]
    public async Task ScanAsync_EngineUnavailable_ReportsUnavailableCapability()
    {
        var engine = new FakeYaraEngine(isAvailable: false);
        var scanner = new YaraScanner(engine, customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        var capability = Assert.Single(data.Capabilities);
        Assert.Equal("libyara", capability.SourceName);
        Assert.Equal(CapabilityStatus.Unavailable, capability.Status);
        Assert.Empty(data.YaraMatches);
    }

    [Fact]
    public async Task ScanAsync_EngineCompileFails_ReportsUnavailableCapabilityAndWarning()
    {
        var engine = new FakeYaraEngine(isAvailable: true, compileError: "syntax error");
        var scanner = new YaraScanner(engine, customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        var capability = Assert.Single(data.Capabilities);
        Assert.Equal("yara-rules", capability.SourceName);
        Assert.Equal(CapabilityStatus.Unavailable, capability.Status);
        Assert.Contains(data.Warnings, w => w.Contains("syntax error"));
    }

    [Fact]
    public async Task ScanAsync_UsesProcExePathForRunningProcessTargets()
    {
        var engine = new FakeYaraEngine(
            scanResults: new Dictionary<string, IReadOnlyList<YaraMatchDetail>>
            {
                ["/proc/123/exe"] = new[] { new YaraMatchDetail { RuleIdentifier = "test_rule" } }
            });
        var scanner = new YaraScanner(
            engine,
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>
            {
                new("/proc/123/exe", "RunningProcess", 123, "/tmp/deleted-malware")
            }));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        var match = Assert.Single(data.YaraMatches);
        Assert.Equal("/proc/123/exe", engine.ScannedPaths.Single());
        Assert.Equal("/proc/123/exe", match.TargetPath);
        Assert.Equal("/tmp/deleted-malware", match.ResolvedTargetPath);
        Assert.Equal(123, match.ProcessId);
    }

    [Fact]
    public async Task DiscoverSuidSgidBinariesAsync_ParsesStdoutWhenFindReturnsPartialFailure()
    {
        var path = Path.Combine(Path.GetTempPath(), $"yara-suid-{Guid.NewGuid()}");
        File.WriteAllText(path, "test");
        try
        {
            var scanner = new YaraScanner(
                new FakeYaraEngine(),
                customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
                commandRunner: (_, _, _) => Task.FromResult<(string?, string?, bool)>(($"{path}\n", "find: /proc: Permission denied", false)));
            var builder = new ScanDataBuilder();

            var targets = await scanner.DiscoverSuidSgidBinariesAsync(builder, CancellationToken.None);

            var target = Assert.Single(targets);
            Assert.Equal(path, target.ScanPath);
            Assert.Equal("SuidBinary", target.TargetKind);
            var data = builder.Build();
            Assert.Contains(data.Warnings, w => w.Contains("Permission denied", StringComparison.Ordinal));
            Assert.Contains(data.Capabilities, c => c.SourceName == "yara-suid-sgid" && c.Status == CapabilityStatus.PermissionLimited);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public void DiscoverRunningProcessExecutables_UsesProcExeAsScanPathAndResolvedPathAsDisplayPath()
    {
        var procRoot = Path.Combine(Path.GetTempPath(), $"proc-{Guid.NewGuid()}");
        var procDir = Path.Combine(procRoot, "123");
        var exe = Path.Combine(Path.GetTempPath(), $"proc-exe-{Guid.NewGuid()}");
        Directory.CreateDirectory(procDir);
        File.WriteAllText(exe, "test");
        try
        {
            var exeLink = Path.Combine(procDir, "exe");
            File.CreateSymbolicLink(exeLink, exe);

            var targets = YaraScanner.DiscoverRunningProcessExecutables(procRoot);

            var target = Assert.Single(targets);
            Assert.Equal(exeLink, target.ScanPath);
            Assert.Equal(exe, target.DisplayPath);
            Assert.Equal("RunningProcess", target.TargetKind);
            Assert.Equal(123, target.ProcessId);
        }
        finally
        {
            try { Directory.Delete(procRoot, recursive: true); } catch { }
            try { File.Delete(exe); } catch { }
        }
    }

    [Fact]
    public void Constructor_InvalidCommandTimeout_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraScanner(null, TimeSpan.Zero));
    }

    [Fact]
    public void Constructor_InvalidMaxOutputChars_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new YaraScanner(null, maxOutputChars: 0));
    }

    private sealed class FakeYaraEngine : IYaraEngine
    {
        private readonly bool _isAvailable;
        private readonly string? _compileError;
        private readonly IReadOnlyDictionary<string, IReadOnlyList<YaraMatchDetail>> _scanResults;

        public FakeYaraEngine(
            bool isAvailable = true,
            string? compileError = null,
            IReadOnlyDictionary<string, IReadOnlyList<YaraMatchDetail>>? scanResults = null)
        {
            _isAvailable = isAvailable;
            _compileError = compileError;
            _scanResults = scanResults ?? new Dictionary<string, IReadOnlyList<YaraMatchDetail>>();
        }

        public List<string> ScannedPaths { get; } = new();

        public bool IsAvailable => _isAvailable;

        public IReadOnlyList<string> CompileRules(string rulesText, string? @namespace = null)
        {
            return _compileError != null ? new[] { _compileError } : Array.Empty<string>();
        }

        public IReadOnlyList<YaraMatchDetail> ScanFile(string path, int timeoutSeconds = 30, CancellationToken cancellationToken = default)
        {
            ScannedPaths.Add(path);
            return _scanResults.TryGetValue(path, out var matches) ? matches : Array.Empty<YaraMatchDetail>();
        }

        public void Dispose()
        {
        }
    }
}
