using System.Reflection;
using VulcansTrace.Linux.Agent;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans security-interesting files and running process executables with YARA rules.
/// Targets: SUID/SGID binaries, /proc/&lt;pid&gt;/exe, and cron script directories.
/// </summary>
public sealed class YaraScanner : IScanner
{
    private const int DefaultMaxOutputChars = 1_048_576;
    private static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan DefaultFileScanTimeout = TimeSpan.FromSeconds(30);

    private readonly IYaraEngine _engine;
    private readonly TimeSpan _commandTimeout;
    private readonly int _maxOutputChars;
    private readonly string _customRulesDirectory;
    private readonly Func<string, string[], CancellationToken, Task<(string? Stdout, string? Stderr, bool Success)>> _commandRunner;
    private readonly Func<ScanDataBuilder, CancellationToken, Task<List<YaraScanTarget>>>? _targetDiscoveryOverride;

    /// <summary>
    /// Initializes a new instance of the <see cref="YaraScanner"/> class.
    /// </summary>
    public YaraScanner()
        : this(null, null, DefaultMaxOutputChars)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="YaraScanner"/> class.
    /// </summary>
    /// <param name="engine">Optional YARA engine override (used for testing).</param>
    /// <param name="commandTimeout">Timeout for target-discovery commands such as find.</param>
    /// <param name="maxOutputChars">Maximum captured output characters for discovery commands.</param>
    /// <param name="customRulesDirectory">Directory containing optional custom .yar files.</param>
    internal YaraScanner(
        IYaraEngine? engine,
        TimeSpan? commandTimeout = null,
        int maxOutputChars = DefaultMaxOutputChars,
        string? customRulesDirectory = null,
        Func<string, string[], CancellationToken, Task<(string? Stdout, string? Stderr, bool Success)>>? commandRunner = null,
        Func<ScanDataBuilder, CancellationToken, Task<List<YaraScanTarget>>>? targetDiscoveryOverride = null)
    {
        _engine = engine ?? new LibyaraEngine();
        _commandTimeout = commandTimeout ?? DefaultCommandTimeout;
        if (_commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(commandTimeout), "Command timeout must be positive.");
        if (maxOutputChars <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxOutputChars), "Maximum output size must be positive.");

        _maxOutputChars = maxOutputChars;
        _customRulesDirectory = customRulesDirectory ?? GetDefaultCustomRulesDirectory();
        _commandRunner = commandRunner ?? RunScannerCommandAsync;
        _targetDiscoveryOverride = targetDiscoveryOverride;
    }

    /// <summary>Resolved directory used for optional custom .yar rules.</summary>
    internal string CustomRulesDirectory => _customRulesDirectory;

    /// <inheritdoc />
    public string Name => "Yara";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        if (!_engine.IsAvailable)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "libyara",
                Status = CapabilityStatus.Unavailable,
                Detail = "libyara shared library is not installed or could not be loaded."
            });
            return;
        }

        var rulesText = await LoadRulesTextAsync(builder, cancellationToken);
        if (string.IsNullOrWhiteSpace(rulesText))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "yara-rules",
                Status = CapabilityStatus.Unavailable,
                Detail = "No bundled or custom YARA rules could be loaded."
            });
            return;
        }

        var compileErrors = _engine.CompileRules(rulesText);
        if (compileErrors.Count > 0)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "yara-rules",
                Status = CapabilityStatus.Unavailable,
                Detail = string.Join("; ", compileErrors)
            });
            builder.AddWarning($"YARA rule compilation failed: {string.Join("; ", compileErrors)}");
            return;
        }

        var targets = await DiscoverTargetsAsync(builder, cancellationToken);
        if (targets.Count == 0)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "yara-scan",
                Status = CapabilityStatus.Available,
                Detail = "No targets discovered."
            });
            return;
        }

        var scanned = 0;
        var matchCount = 0;
        var errors = new List<string>();
        var semaphore = new SemaphoreSlim(8, 8);

        try
        {
            var tasks = targets.Select(async target =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var matches = _engine.ScanFile(target.ScanPath, (int)DefaultFileScanTimeout.TotalSeconds, cancellationToken);
                    Interlocked.Increment(ref scanned);

                    foreach (var match in matches)
                    {
                        Interlocked.Increment(ref matchCount);
                        builder.AddYaraMatch(new YaraMatchEntry
                        {
                            TargetPath = target.ScanPath,
                            ResolvedTargetPath = target.DisplayPath,
                            TargetKind = target.TargetKind,
                            RuleIdentifier = match.RuleIdentifier,
                            ProcessId = target.ProcessId,
                            MatchDescription = match.Description
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    lock (errors)
                    {
                        errors.Add($"YARA scan failed for {target.ScanPath}: {ex.Message}");
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks);
        }
        finally
        {
            semaphore.Dispose();
        }

        foreach (var error in errors.Take(5))
        {
            builder.AddWarning(error);
        }

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "yara-scan",
            Status = errors.Count > 0 ? CapabilityStatus.PermissionLimited : CapabilityStatus.Available,
            Detail = $"Scanned {scanned} target(s), {matchCount} match(es), {errors.Count} error(s)."
        });
    }

    private async Task<string> LoadRulesTextAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var parts = new List<string>();

        var bundled = LoadBundledRules();
        if (!string.IsNullOrWhiteSpace(bundled))
        {
            parts.Add(bundled);
        }

        if (Directory.Exists(_customRulesDirectory))
        {
            try
            {
                var files = Directory.GetFiles(_customRulesDirectory, "*.yar", SearchOption.TopDirectoryOnly);
                foreach (var file in files.OrderBy(f => f, StringComparer.Ordinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var content = await File.ReadAllTextAsync(file, cancellationToken);
                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            parts.Add(content);
                        }
                    }
                    catch (Exception ex)
                    {
                        builder.AddWarning($"Failed to load custom YARA rule '{file}': {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                builder.AddWarning($"Failed to enumerate custom YARA rules directory: {ex.Message}");
            }
        }

        return string.Join("\n\n", parts);
    }

    private static string LoadBundledRules()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("bundled.yar", StringComparison.OrdinalIgnoreCase));

        if (resourceName == null)
            return string.Empty;

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
            return string.Empty;

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private async Task<List<YaraScanTarget>> DiscoverTargetsAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var targets = new List<YaraScanTarget>();

        if (_targetDiscoveryOverride != null)
            return await _targetDiscoveryOverride(builder, cancellationToken);

        var suidSgid = await DiscoverSuidSgidBinariesAsync(builder, cancellationToken);
        targets.AddRange(suidSgid);

        cancellationToken.ThrowIfCancellationRequested();

        var processes = DiscoverRunningProcessExecutables();
        targets.AddRange(processes);

        cancellationToken.ThrowIfCancellationRequested();

        var cronScripts = DiscoverCronScripts();
        targets.AddRange(cronScripts);

        return targets
            .GroupBy(t => t.ScanPath, StringComparer.Ordinal)
            .Select(g => g.First())
            .OrderBy(t => t.ScanPath, StringComparer.Ordinal)
            .ToList();
    }

    internal async Task<List<YaraScanTarget>> DiscoverSuidSgidBinariesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var targets = new List<YaraScanTarget>();
        var (stdout, stderr, success) = await RunCommandAsync("find", new[]
        {
            "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"
        }, cancellationToken);

        if (!success && !string.IsNullOrWhiteSpace(stderr))
        {
            builder.AddWarning($"YARA SUID/SGID discovery warning: {stderr.Trim()}");
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "yara-suid-sgid",
                Status = CapabilityStatus.PermissionLimited,
                Detail = "SUID/SGID discovery returned partial results."
            });
        }

        if (string.IsNullOrWhiteSpace(stdout))
            return targets;

        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var path = line.Trim();
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                targets.Add(new YaraScanTarget(path, "SuidBinary", DisplayPath: path));
            }
        }

        return targets;
    }

    internal static List<YaraScanTarget> DiscoverRunningProcessExecutables(string procRoot = "/proc")
    {
        var targets = new List<YaraScanTarget>();
        try
        {
            foreach (var dir in Directory.GetDirectories(procRoot))
            {
                var name = Path.GetFileName(dir);
                if (!int.TryParse(name, out var pid))
                    continue;

                var exeLink = Path.Combine(dir, "exe");
                try
                {
                    var info = File.ResolveLinkTarget(exeLink, returnFinalTarget: true);
                    if (info == null)
                        continue;

                    var path = info.FullName;
                    targets.Add(new YaraScanTarget(exeLink, "RunningProcess", pid, path));
                }
                catch (FileNotFoundException)
                {
                    // Kernel threads or exited processes have no exe.
                }
                catch (UnauthorizedAccessException)
                {
                    // Ignore permission-limited processes.
                }
                catch
                {
                    // Ignore other per-process errors to keep enumeration robust.
                }
            }
        }
        catch
        {
            // Ignore top-level /proc enumeration failures.
        }

        return targets;
    }

    private static List<YaraScanTarget> DiscoverCronScripts()
    {
        var targets = new List<YaraScanTarget>();
        var directories = new[]
        {
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly"
        };

        foreach (var directory in directories)
        {
            try
            {
                if (!Directory.Exists(directory))
                    continue;

                foreach (var file in Directory.GetFiles(directory))
                {
                    if (File.Exists(file))
                    {
                        targets.Add(new YaraScanTarget(file, "CronScript", DisplayPath: file));
                    }
                }
            }
            catch
            {
                // Ignore per-directory enumeration errors.
            }
        }

        return targets;
    }

    private async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await _commandRunner(fileName, args, ct);
    }

    private Task<(string? Stdout, string? Stderr, bool Success)> RunScannerCommandAsync(
        string fileName,
        string[] args,
        CancellationToken ct)
    {
        return ScannerCommandRunner.RunAsync(fileName, args, ct, _commandTimeout, _maxOutputChars);
    }

    private static string GetDefaultCustomRulesDirectory()
        => Path.Combine(VulcansTraceConfig.GetDirectory(), "yara");

    internal sealed record YaraScanTarget(string ScanPath, string TargetKind, int? ProcessId = null, string DisplayPath = "");
}
