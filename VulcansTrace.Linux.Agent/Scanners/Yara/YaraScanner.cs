using System.Reflection;
using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans security-interesting files and running process executables with YARA rules.
/// Targets: SUID/SGID binaries, /proc/&lt;pid&gt;/exe, and cron script directories.
/// </summary>
public sealed partial class YaraScanner : IScanner
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
                Detail = "libyara shared library is not installed or could not be loaded.",
                Command = "libyara scan"
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
                Detail = "No bundled or custom YARA rules could be loaded.",
                Command = "yara-rules"
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
                Detail = string.Join("; ", compileErrors),
                Command = "yara-rules"
            });
            builder.AddWarning($"YARA rule compilation failed: {string.Join("; ", compileErrors)}");
            return;
        }

        var discovery = await DiscoverTargetsAsync(builder, cancellationToken);
        var targets = discovery.Targets;
        if (targets.Count == 0)
        {
            builder.SetYaraScanCompleted(discovery.Complete);
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "yara-scan",
                Status = discovery.Complete ? CapabilityStatus.Available : CapabilityStatus.PermissionLimited,
                Detail = discovery.Complete
                    ? "No targets discovered."
                    : "No targets discovered; target discovery was incomplete.",
                Command = "yara <rules> <targets>"
            });
            return;
        }

        var scanned = 0;
        var matchCount = 0;
        var errors = new List<string>();
        var transientProcessSkips = 0;
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
                    // Running-process targets routinely vanish between enumeration and scan (the process
                    // exits, /proc/<pid>/exe disappears, libyara returns error 3). That is benign churn, not
                    // a scanner failure, so count it quietly instead of surfacing it as a scanner warning
                    // (which would otherwise read as "N scanners returned unexpected errors").
                    if (IsTransientProcessExitFailure(target, ex))
                    {
                        Interlocked.Increment(ref transientProcessSkips);
                    }
                    else
                    {
                        lock (errors)
                        {
                            errors.Add($"YARA scan failed for {target.ScanPath}: {ex.Message}");
                        }
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

        var detail = $"Scanned {scanned} target(s), {matchCount} match(es), {errors.Count} error(s)";
        if (transientProcessSkips > 0)
            detail += $", {transientProcessSkips} transient process target(s) skipped";

        var completed = discovery.Complete && errors.Count == 0 && transientProcessSkips == 0;
        builder.SetYaraScanCompleted(completed);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "yara-scan",
            Status = completed ? CapabilityStatus.Available : CapabilityStatus.PermissionLimited,
            Detail = detail + ".",
            Command = "yara <rules> <targets>"
        });
    }

    /// <summary>
    /// True when a RunningProcess target failed because its executable vanished between enumeration and
    /// scan — a process exiting mid-scan. Matches libyara's "could not open file" (error 3) and the .NET
    /// file-not-found exceptions raised when the /proc/&lt;pid&gt;/exe symlink target is already gone.
    /// </summary>
    private static bool IsTransientProcessExitFailure(YaraScanTarget target, Exception ex)
    {
        if (!string.Equals(target.TargetKind, "RunningProcess", StringComparison.OrdinalIgnoreCase))
            return false;

        if (ex is FileNotFoundException or DirectoryNotFoundException)
            return true;

        var message = ex.Message ?? string.Empty;
        if (message.Contains("permission denied", StringComparison.OrdinalIgnoreCase)
            || message.Contains("access denied", StringComparison.OrdinalIgnoreCase)
            || message.Contains("operation not permitted", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return message.Contains("could not open file", StringComparison.OrdinalIgnoreCase)
            || message.Contains("no such file", StringComparison.OrdinalIgnoreCase)
            || message.Contains("could not find file", StringComparison.OrdinalIgnoreCase)
            || Error3Pattern().IsMatch(message);
    }

    // libyara's "error 3" exactly — a bare substring would also swallow "error 30"/"error 31"
    // (genuine failures) on RunningProcess targets.
    [GeneratedRegex(@"\berror 3\b", RegexOptions.IgnoreCase)]
    private static partial Regex Error3Pattern();

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

    private async Task<YaraTargetDiscoveryResult> DiscoverTargetsAsync(
        ScanDataBuilder builder,
        CancellationToken cancellationToken)
    {
        var targets = new List<YaraScanTarget>();

        if (_targetDiscoveryOverride != null)
        {
            return new YaraTargetDiscoveryResult(
                await _targetDiscoveryOverride(builder, cancellationToken),
                Complete: true);
        }

        var suidSgid = await DiscoverSuidSgidBinariesWithStatusAsync(builder, cancellationToken);
        targets.AddRange(suidSgid.Targets);

        cancellationToken.ThrowIfCancellationRequested();

        var processes = DiscoverRunningProcessExecutablesWithStatus("/proc");
        targets.AddRange(processes.Targets);

        cancellationToken.ThrowIfCancellationRequested();

        var cronScripts = DiscoverCronScripts();
        targets.AddRange(cronScripts.Targets);

        var uniqueTargets = targets
            .GroupBy(t => t.ScanPath, StringComparer.Ordinal)
            .Select(g => g.First())
            .OrderBy(t => t.ScanPath, StringComparer.Ordinal)
            .ToList();

        return new YaraTargetDiscoveryResult(
            uniqueTargets,
            suidSgid.Complete && processes.Complete && cronScripts.Complete);
    }

    internal async Task<List<YaraScanTarget>> DiscoverSuidSgidBinariesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        => (await DiscoverSuidSgidBinariesWithStatusAsync(builder, cancellationToken)).Targets;

    private async Task<YaraTargetDiscoveryResult> DiscoverSuidSgidBinariesWithStatusAsync(
        ScanDataBuilder builder,
        CancellationToken cancellationToken)
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
                Detail = "SUID/SGID discovery returned partial results.",
                Command = "find / -xdev ( -perm -4000 -o -perm -2000 ) -type f"
            });
        }

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var path = line.Trim();
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    targets.Add(new YaraScanTarget(path, "SuidBinary", DisplayPath: path));
                }
            }
        }

        return new YaraTargetDiscoveryResult(targets, Complete: success);
    }

    internal static List<YaraScanTarget> DiscoverRunningProcessExecutables(string procRoot = "/proc")
        => DiscoverRunningProcessExecutablesWithStatus(procRoot).Targets;

    private static YaraTargetDiscoveryResult DiscoverRunningProcessExecutablesWithStatus(string procRoot)
    {
        var targets = new List<YaraScanTarget>();
        var complete = true;
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
                    complete = false;
                }
                catch
                {
                    complete = false;
                }
            }
        }
        catch
        {
            complete = false;
        }

        return new YaraTargetDiscoveryResult(targets, complete);
    }

    private static YaraTargetDiscoveryResult DiscoverCronScripts()
    {
        var targets = new List<YaraScanTarget>();
        var complete = true;
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
                complete = false;
            }
        }

        return new YaraTargetDiscoveryResult(targets, complete);
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

    private sealed record YaraTargetDiscoveryResult(List<YaraScanTarget> Targets, bool Complete);
}
