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
        Assert.False(data.YaraScanCompleted);
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
        Assert.True(data.YaraScanCompleted);
        Assert.Equal("/proc/123/exe", engine.ScannedPaths.Single());
        Assert.Equal("/proc/123/exe", match.TargetPath);
        Assert.Equal("/tmp/deleted-malware", match.ResolvedTargetPath);
        Assert.Equal(123, match.ProcessId);
    }

    [Fact]
    public async Task ScanAsync_RunningProcessVanishes_CountedAsTransientWithoutWarning()
    {
        // A RunningProcess target whose /proc/<pid>/exe vanishes mid-scan (process exited, libyara
        // error 3 / FileNotFoundException) is benign churn — it must be counted quietly, NOT surfaced
        // as a scanner warning (which would read as "N scanners returned unexpected errors").
        var engine = new FakeYaraEngine(scanException: new FileNotFoundException(
            "could not open file: /proc/123/exe (libyara error 3)"));
        var scanner = new YaraScanner(
            engine,
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>
            {
                new("/proc/123/exe", "RunningProcess", 123, "/tmp/gone")
            }));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.Empty(data.Warnings);
        var cap = Assert.Single(data.Capabilities, c => c.SourceName == "yara-scan");
        Assert.Equal(CapabilityStatus.PermissionLimited, cap.Status);
        Assert.Contains("0 error(s)", cap.Detail);
        Assert.Contains("1 transient process target(s) skipped", cap.Detail);
        Assert.False(data.YaraScanCompleted);
    }

    [Fact]
    public async Task ScanAsync_NonTransientFailure_StillWarns()
    {
        // Guard against over-suppression: a genuine failure on a non-process target (e.g. a SUID
        // binary the engine can't scan) must still surface as a warning, not be swallowed as transient.
        var engine = new FakeYaraEngine(scanException: new InvalidOperationException("scan engine fault"));
        var scanner = new YaraScanner(
            engine,
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>
            {
                new("/usr/bin/suid-bin", "SuidBinary", null, "/usr/bin/suid-bin")
            }));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.Contains(data.Warnings, w => w.Contains("YARA scan failed", StringComparison.Ordinal));
        var cap = Assert.Single(data.Capabilities, c => c.SourceName == "yara-scan");
        Assert.Equal(CapabilityStatus.PermissionLimited, cap.Status);
        Assert.Contains("1 error(s)", cap.Detail);
    }

    [Fact]
    public async Task ScanAsync_RunningProcessError30_StillWarns()
    {
        // Guard the tightened transient matcher: libyara "error 30" on a process target is a genuine
        // failure, NOT benign exit churn — a bare "error 3" substring would wrongly swallow it.
        var engine = new FakeYaraEngine(scanException: new InvalidOperationException(
            "yr_rules_scan_file failed with error 30 for '/proc/123/exe'"));
        var scanner = new YaraScanner(
            engine,
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>
            {
                new("/proc/123/exe", "RunningProcess", 123, "/tmp/exe")
            }));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.Contains(data.Warnings, w => w.Contains("YARA scan failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanAsync_RunningProcessPermissionError3_StillWarns()
    {
        var engine = new FakeYaraEngine(scanException: new UnauthorizedAccessException(
            "could not open file: permission denied (libyara error 3)"));
        var scanner = new YaraScanner(
            engine,
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>
            {
                new("/proc/123/exe", "RunningProcess", 123, "/tmp/exe")
            }));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.Contains(data.Warnings, w => w.Contains("permission denied", StringComparison.OrdinalIgnoreCase));
        Assert.False(data.YaraScanCompleted);
    }

    [Fact]
    public async Task ScanAsync_NoTargets_CompletesCleanScan()
    {
        var scanner = new YaraScanner(
            new FakeYaraEngine(),
            customRulesDirectory: Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()),
            targetDiscoveryOverride: (_, _) => Task.FromResult(new List<YaraScanner.YaraScanTarget>()));
        var builder = new ScanDataBuilder();

        await scanner.ScanAsync(builder, CancellationToken.None);

        var data = builder.Build();
        Assert.True(data.YaraScanCompleted);
        Assert.Contains(data.Capabilities, c => c.SourceName == "yara-scan"
            && c.Status == CapabilityStatus.Available);
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
        private readonly Exception? _scanException;

        public FakeYaraEngine(
            bool isAvailable = true,
            string? compileError = null,
            IReadOnlyDictionary<string, IReadOnlyList<YaraMatchDetail>>? scanResults = null,
            Exception? scanException = null)
        {
            _isAvailable = isAvailable;
            _compileError = compileError;
            _scanResults = scanResults ?? new Dictionary<string, IReadOnlyList<YaraMatchDetail>>();
            _scanException = scanException;
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
            if (_scanException is not null)
                throw _scanException;
            return _scanResults.TryGetValue(path, out var matches) ? matches : Array.Empty<YaraMatchDetail>();
        }

        public void Dispose()
        {
        }
    }
}
