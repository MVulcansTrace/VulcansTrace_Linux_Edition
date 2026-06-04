using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Computes SHA-256 hashes of security-interesting files discovered on the system.
/// Targets SUID/SGID binaries, world-writable files, unowned files, and cron scripts.
/// </summary>
public sealed class FileHashScanner : IScanner
{
    private const int DefaultMaxOutputChars = 2_097_152; // 2 MiB for hash output
    private static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromSeconds(120);
    private readonly IThreatIntelStore? _threatIntelStore;
    private readonly TimeSpan _commandTimeout;
    private readonly int _maxOutputChars;

    /// <summary>
    /// Initializes a new instance of the <see cref="FileHashScanner"/> class.
    /// </summary>
    /// <param name="commandTimeout">Maximum runtime for hash commands. Defaults to 120 seconds.</param>
    /// <param name="maxOutputChars">Maximum captured stdout characters. Defaults to 2 MiB.</param>
    public FileHashScanner(TimeSpan? commandTimeout = null, int maxOutputChars = DefaultMaxOutputChars)
        : this(null, commandTimeout, maxOutputChars)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FileHashScanner"/> class.
    /// </summary>
    /// <param name="threatIntelStore">Optional threat intel store used to skip hashing when no file hash IOCs are loaded.</param>
    /// <param name="commandTimeout">Maximum runtime for hash commands. Defaults to 120 seconds.</param>
    /// <param name="maxOutputChars">Maximum captured stdout characters. Defaults to 2 MiB.</param>
    public FileHashScanner(IThreatIntelStore? threatIntelStore, TimeSpan? commandTimeout = null, int maxOutputChars = DefaultMaxOutputChars)
    {
        _threatIntelStore = threatIntelStore;
        _commandTimeout = commandTimeout ?? DefaultCommandTimeout;
        if (_commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(commandTimeout), "Command timeout must be positive.");
        if (maxOutputChars <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxOutputChars), "Maximum output size must be positive.");

        _maxOutputChars = maxOutputChars;
    }

    /// <inheritdoc />
    public string Name => "FileHash";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        if (_threatIntelStore != null && _threatIntelStore.CountByType(IocType.FileHash) == 0)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "file-hash",
                Status = CapabilityStatus.Unknown,
                Detail = "Skipped because no imported file-hash IOCs are loaded."
            });
            return;
        }

        var files = await DiscoverFilesAsync(builder, cancellationToken);
        if (files.Count == 0)
            return;

        await HashFilesAsync(builder, files, cancellationToken);
    }

    private async Task<List<string>> DiscoverFilesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var files = new HashSet<string>(StringComparer.Ordinal);
        var warnings = new List<string>();

        // SUID/SGID binaries
        var suid = await RunFindAsync(new[] { "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f" }, cancellationToken);
        CollectFiles(suid, files, warnings);

        // World-writable files
        var ww = await RunFindAsync(new[] { "/", "-xdev", "-type", "f", "-perm", "-002" }, cancellationToken);
        CollectFiles(ww, files, warnings);

        // Unowned files
        var unowned = await RunFindAsync(new[] { "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")", "-type", "f" }, cancellationToken);
        CollectFiles(unowned, files, warnings);

        // Cron scripts
        var cronScripts = await RunFindAsync(new[] { 
            "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
            "-maxdepth", "2", "-type", "f"
        }, cancellationToken);
        CollectFiles(cronScripts, files, warnings);

        if (warnings.Count > 0)
        {
            foreach (var w in warnings)
                builder.AddWarning(w);
        }

        return files.ToList();
    }

    private static void CollectFiles((string? Stdout, string? Stderr, bool Success) result, HashSet<string> files, List<string> warnings)
    {
        if (!result.Success)
        {
            if (!string.IsNullOrWhiteSpace(result.Stderr))
                warnings.Add($"FileHash find warning: {result.Stderr.Trim()}");
            return;
        }

        if (!string.IsNullOrWhiteSpace(result.Stdout))
        {
            foreach (var line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    files.Add(trimmed);
            }
        }
    }

    private async Task HashFilesAsync(ScanDataBuilder builder, List<string> files, CancellationToken cancellationToken)
    {
        // Batch files to avoid command-line length limits
        const int batchSize = 100;
        var hashed = 0;
        var failed = 0;

        for (int i = 0; i < files.Count; i += batchSize)
        {
            var batch = files.Skip(i).Take(batchSize).ToList();

            // SHA-256
            var sha256 = await HashBatchAsync("sha256sum", batch, 64, "SHA-256", cancellationToken);
            if (sha256.Count == 0)
            {
                // Fallback to openssl if sha256sum is unavailable
                sha256 = await HashBatchWithOpenSslAsync(batch, cancellationToken);
            }
            foreach (var entry in sha256)
            {
                builder.AddFileHash(entry);
                hashed++;
            }

            // MD5
            var md5 = await HashBatchAsync("md5sum", batch, 32, "MD5", cancellationToken);
            foreach (var entry in md5)
            {
                builder.AddFileHash(entry);
                hashed++;
            }

            // SHA-1
            var sha1 = await HashBatchAsync("sha1sum", batch, 40, "SHA-1", cancellationToken);
            foreach (var entry in sha1)
            {
                builder.AddFileHash(entry);
                hashed++;
            }

            if (sha256.Count == 0 && md5.Count == 0 && sha1.Count == 0)
            {
                failed += batch.Count;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "file-hash",
            Status = failed > 0 ? CapabilityStatus.PermissionLimited : CapabilityStatus.Available,
            Detail = $"Hashed {hashed} files, {failed} failed."
        });
    }

    private async Task<List<FileHashEntry>> HashBatchAsync(string command, List<string> batch, int expectedLength, string algorithm, CancellationToken cancellationToken)
    {
        var entries = new List<FileHashEntry>();
        var (stdout, _, success) = await RunCommandAsync(command, batch.ToArray(), cancellationToken);
        if (!success || string.IsNullOrWhiteSpace(stdout))
            return entries;

        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parsed = ParseHashLine(line.Trim(), expectedLength, algorithm);
            if (parsed != null)
                entries.Add(parsed);
        }
        return entries;
    }

    private async Task<List<FileHashEntry>> HashBatchWithOpenSslAsync(List<string> files, CancellationToken cancellationToken)
    {
        var entries = new List<FileHashEntry>();
        foreach (var file in files)
        {
            var (stdout, _, success) = await RunCommandAsync("openssl", new[] { "dgst", "-sha256", file }, cancellationToken);
            if (success && !string.IsNullOrWhiteSpace(stdout))
            {
                // openssl output: "SHA256(filename)= hashhex"
                var hashPart = stdout.Split('=').LastOrDefault()?.Trim();
                if (!string.IsNullOrWhiteSpace(hashPart) && hashPart.Length == 64)
                {
                    entries.Add(new FileHashEntry
                    {
                        Path = file,
                        Hash = hashPart.ToLowerInvariant(),
                        Algorithm = "SHA-256"
                    });
                }
            }
        }
        return entries;
    }

    internal static FileHashEntry? ParseHashLine(string line)
        => ParseHashLine(line, 64, "SHA-256");

    internal static FileHashEntry? ParseHashLine(string line, int expectedLength, string algorithm)
    {
        // Expected format: "<hash>  <filepath>"
        var firstSpace = line.IndexOf("  ", StringComparison.Ordinal);
        if (firstSpace <= 0)
            return null;

        var hash = line[..firstSpace].Trim().ToLowerInvariant();
        var path = line[(firstSpace + 2)..].Trim();

        if (hash.Length != expectedLength || string.IsNullOrWhiteSpace(path))
            return null;

        return new FileHashEntry
        {
            Path = path,
            Hash = hash,
            Algorithm = algorithm
        };
    }

    private async Task<(string? Stdout, string? Stderr, bool Success)> RunFindAsync(string[] args, CancellationToken ct)
    {
        return await RunCommandAsync("find", args, ct);
    }

    private async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct, _commandTimeout, _maxOutputChars);
    }
}
