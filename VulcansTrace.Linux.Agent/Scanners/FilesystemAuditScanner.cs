using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans the filesystem for permission anomalies: world-writable files outside expected paths,
/// unexpected SUID/SGID binaries, unowned files, world-writable directories without sticky bit,
/// and /tmp mount hardening.
///
/// Design notes / limitations:
/// • Uses -xdev to avoid crossing filesystem boundaries (network mounts, etc.). SUID binaries
///   on separate /home, /usr, or /opt mounts are only visible if they share the root filesystem.
/// • Container overlay filesystems under /var/lib/docker/ are scanned as part of root filesystem.
/// • Filenames containing newlines may break line-based parsing; this is a known edge case.
/// • SUID whitelist is hardcoded; custom legitimate SUID binaries may trigger false positives.
/// </summary>
public sealed class FilesystemAuditScanner : IScanner
{
    private const int DefaultMaxOutputChars = 1_048_576;
    private static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromSeconds(60);
    private readonly TimeSpan _commandTimeout;
    private readonly int _maxOutputChars;

    /// <summary>
    /// Initializes a new instance of the <see cref="FilesystemAuditScanner"/> class.
    /// </summary>
    /// <param name="commandTimeout">Maximum runtime for each filesystem command. Defaults to 60 seconds.</param>
    /// <param name="maxOutputChars">Maximum captured stdout or stderr characters per command. Defaults to 1 MiB.</param>
    public FilesystemAuditScanner(TimeSpan? commandTimeout = null, int maxOutputChars = DefaultMaxOutputChars)
    {
        _commandTimeout = commandTimeout ?? DefaultCommandTimeout;
        if (_commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(commandTimeout), "Command timeout must be positive.");
        if (maxOutputChars <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxOutputChars), "Maximum output size must be positive.");

        _maxOutputChars = maxOutputChars;
    }

    /// <inheritdoc />
    public string Name => "FilesystemAudit";

    private static readonly string[] WorldWritableExpectedPrefixes =
    {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/var/cache/", "/var/spool/"
    };

    private static readonly string[] WorldWritableExpectedPaths =
    {
        "/tmp", "/var/tmp", "/dev/shm", "/var/cache", "/var/spool"
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var tasks = new List<Task>
        {
            ScanWorldWritableFilesAsync(builder, cancellationToken),
            ScanSuidSgidBinariesAsync(builder, cancellationToken),
            ScanUnownedFilesAsync(builder, cancellationToken),
            ScanWorldWritableDirsNoStickyAsync(builder, cancellationToken),
            ScanTmpMountAsync(builder, cancellationToken)
        };

        await Task.WhenAll(tasks);
    }

    private async Task ScanWorldWritableFilesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (stdout, stderr, success) = await RunFindAsync(
            new[] { "/", "-xdev", "-type", "f", "-perm", "-002", "-exec", "stat", "-c", "%a %U %G %n", "{}", "+" },
            cancellationToken);

        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);
        if (!string.IsNullOrWhiteSpace(stderr) && DataSourceCapability.ContainsPermissionDenied(stderr))
            status = CapabilityStatus.PermissionLimited;

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "find-world-writable-files",
            Status = status,
            Detail = stderr
        });

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = FilePermissionScanner.ParseStatLine(line.Trim());
                if (entry == null) continue;
                if (!seen.Add(entry.Path)) continue;
                if (IsExpectedWorldWritablePath(entry.Path)) continue;

                builder.AddFilesystemAudit(new FilesystemAuditEntry
                {
                    Path = entry.Path,
                    Mode = entry.Mode,
                    Owner = entry.Owner,
                    Group = entry.Group,
                    AuditCategory = "WorldWritableFile"
                });
            }
        }
    }

    private async Task ScanSuidSgidBinariesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (stdout, stderr, success) = await RunFindAsync(
            new[] { "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f", "-exec", "stat", "-c", "%a %U %G %n", "{}", "+" },
            cancellationToken);

        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);
        if (!string.IsNullOrWhiteSpace(stderr) && DataSourceCapability.ContainsPermissionDenied(stderr))
            status = CapabilityStatus.PermissionLimited;

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "find-suid-sgid",
            Status = status,
            Detail = stderr
        });

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = FilePermissionScanner.ParseStatLine(line.Trim());
                if (entry == null) continue;
                if (!seen.Add(entry.Path)) continue;
                if (!int.TryParse(entry.Mode, out var mode)) continue;

                var firstDigit = mode / 1000;
                var category = firstDigit switch
                {
                    4 or 5 => "SuidBinary",
                    2 or 3 => "SgidBinary",
                    6 or 7 => "SuidSgidBinary",
                    _ => "SuidBinary"
                };

                builder.AddFilesystemAudit(new FilesystemAuditEntry
                {
                    Path = entry.Path,
                    Mode = entry.Mode,
                    Owner = entry.Owner,
                    Group = entry.Group,
                    AuditCategory = category
                });
            }
        }
    }

    private async Task ScanUnownedFilesAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (stdout, stderr, success) = await RunFindAsync(
            new[] { "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")", "-type", "f", "-exec", "stat", "-c", "%a %U %G %n", "{}", "+" },
            cancellationToken);

        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);
        if (!string.IsNullOrWhiteSpace(stderr) && DataSourceCapability.ContainsPermissionDenied(stderr))
            status = CapabilityStatus.PermissionLimited;

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "find-unowned-files",
            Status = status,
            Detail = stderr
        });

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = FilePermissionScanner.ParseStatLine(line.Trim());
                if (entry == null) continue;
                if (!seen.Add(entry.Path)) continue;

                builder.AddFilesystemAudit(new FilesystemAuditEntry
                {
                    Path = entry.Path,
                    Mode = entry.Mode,
                    Owner = entry.Owner,
                    Group = entry.Group,
                    AuditCategory = "UnownedFile"
                });
            }
        }
    }

    private async Task ScanWorldWritableDirsNoStickyAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (stdout, stderr, success) = await RunFindAsync(
            new[] { "/", "-xdev", "-type", "d", "-perm", "-002", "!", "-perm", "-1000", "-exec", "stat", "-c", "%a %U %G %n", "{}", "+" },
            cancellationToken);

        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);
        if (!string.IsNullOrWhiteSpace(stderr) && DataSourceCapability.ContainsPermissionDenied(stderr))
            status = CapabilityStatus.PermissionLimited;

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "find-world-writable-dirs",
            Status = status,
            Detail = stderr
        });

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = FilePermissionScanner.ParseStatLine(line.Trim());
                if (entry == null) continue;
                if (!seen.Add(entry.Path)) continue;

                builder.AddFilesystemAudit(new FilesystemAuditEntry
                {
                    Path = entry.Path,
                    Mode = entry.Mode,
                    Owner = entry.Owner,
                    Group = entry.Group,
                    AuditCategory = "WorldWritableDirNoSticky"
                });
            }
        }
    }

    private async Task ScanTmpMountAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        // First get the mount target to determine if /tmp is a separate partition
        var (targetOut, targetErr, targetSuccess) = await RunCommandAsync(
            "findmnt", new[] { "-n", "-o", "TARGET", "/tmp" }, cancellationToken);

        if (targetSuccess && !string.IsNullOrWhiteSpace(targetOut))
        {
            builder.SetTmpMountTarget(targetOut.Trim());
        }

        // Then get the mount options
        var (stdout, stderr, success) = await RunCommandAsync(
            "findmnt", new[] { "-n", "-o", "OPTIONS", "/tmp" }, cancellationToken);

        if (!success || string.IsNullOrWhiteSpace(stdout))
        {
            (stdout, stderr, success) = await RunCommandAsync(
                "sh", new[] { "-c", "mount | grep ' on /tmp type ' | sed 's/.*(//;s/).*//'" }, cancellationToken);
        }

        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "findmnt-tmp",
            Status = status,
            Detail = stderr
        });

        if (success && !string.IsNullOrWhiteSpace(stdout))
        {
            builder.SetTmpMountOptions(stdout.Trim());
        }
    }

    private static bool IsExpectedWorldWritablePath(string path)
    {
        // Use Ordinal comparison because Linux filesystems are case-sensitive by default.
        foreach (var expected in WorldWritableExpectedPrefixes)
        {
            if (path.StartsWith(expected, StringComparison.Ordinal))
                return true;
        }
        foreach (var expected in WorldWritableExpectedPaths)
        {
            if (path.Equals(expected, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private async Task<(string? Stdout, string? Stderr, bool Success)> RunFindAsync(
        string[] args, CancellationToken ct)
    {
        return await RunCommandAsync("find", args, ct);
    }

    internal async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi);
            if (process == null)
                return (null, $"Failed to start '{fileName}'.", false);

            var stdout = new System.Text.StringBuilder();
            var stderr = new System.Text.StringBuilder();
            var stdoutChars = 0;
            var stderrChars = 0;
            var stdoutTruncated = false;
            var stderrTruncated = false;
            var outputLock = new object();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    AppendBounded(stdout, e.Data, ref stdoutChars, ref stdoutTruncated, _maxOutputChars, outputLock);
                }
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    AppendBounded(stderr, e.Data, ref stderrChars, ref stderrTruncated, _maxOutputChars, outputLock);
                }
            };

            await using (ct.Register(() =>
            {
                try { process.Kill(); } catch { /* ignore */ }
            }))
            {
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(_commandTimeout);

                try
                {
                    await process.WaitForExitAsync(timeoutCts.Token);
                    await Task.Delay(100, CancellationToken.None);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    try { process.Kill(entireProcessTree: true); } catch { /* ignore */ }
                    AppendLine(stderr, $"Command timed out after {_commandTimeout.TotalSeconds:0.#} seconds.", outputLock);
                    return (stdout.ToString().Trim(), stderr.ToString().Trim(), false);
                }

                ct.ThrowIfCancellationRequested();
                var success = process.ExitCode == 0;
                if (stdoutTruncated)
                    AppendLine(stderr, $"Standard output was truncated after {_maxOutputChars} characters.", outputLock);
                if (stderrTruncated)
                    AppendLine(stderr, $"Standard error was truncated after {_maxOutputChars} characters.", outputLock);

                return (stdout.ToString().Trim(), stderr.ToString().Trim(), success);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return (null, ex.Message, false);
        }
    }

    private static void AppendBounded(
        System.Text.StringBuilder builder,
        string line,
        ref int currentLength,
        ref bool truncated,
        int maxChars,
        object syncRoot)
    {
        lock (syncRoot)
        {
            if (currentLength >= maxChars)
            {
                truncated = true;
                return;
            }

            var remaining = maxChars - currentLength;
            var text = line + Environment.NewLine;
            if (text.Length > remaining)
            {
                builder.Append(text.AsSpan(0, remaining));
                currentLength = maxChars;
                truncated = true;
                return;
            }

            builder.Append(text);
            currentLength += text.Length;
        }
    }

    private static void AppendLine(System.Text.StringBuilder builder, string line, object syncRoot)
    {
        lock (syncRoot)
        {
            if (builder.Length > 0)
                builder.AppendLine();
            builder.Append(line);
        }
    }
}
