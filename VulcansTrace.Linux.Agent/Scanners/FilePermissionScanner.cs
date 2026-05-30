using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans permission bits, ownership, and existence of sensitive files and directories.
/// </summary>
public sealed class FilePermissionScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "FilePermission";

    private static readonly string[] StaticPaths =
    {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/group",
        "/etc/gshadow",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/root/.ssh",
        "/root/.ssh/authorized_keys"
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var pathsToCheck = new List<string>();

        foreach (var path in StaticPaths)
        {
            if (File.Exists(path) || Directory.Exists(path))
                pathsToCheck.Add(path);
        }

        // Enumerate SSH host private keys
        var sshHostKeys = GetSshHostKeyPaths();
        pathsToCheck.AddRange(sshHostKeys);

        // Enumerate user home SSH directories
        var userSshPaths = GetUserSshPaths();
        pathsToCheck.AddRange(userSshPaths);

        if (pathsToCheck.Count == 0)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "stat",
                Status = CapabilityStatus.Unavailable,
                Detail = "No sensitive paths found on this system."
            });
            return;
        }

        await ScanPathsAsync(pathsToCheck, builder, cancellationToken);
    }

    private static List<string> GetSshHostKeyPaths()
    {
        var result = new List<string>();
        try
        {
            if (Directory.Exists("/etc/ssh"))
            {
                var files = Directory.GetFiles("/etc/ssh", "ssh_host_*_key");
                foreach (var file in files)
                {
                    if (!file.EndsWith(".pub", StringComparison.OrdinalIgnoreCase))
                        result.Add(file);
                }
            }
        }
        catch
        {
            // Ignore enumeration errors
        }
        return result;
    }

    private static List<string> GetUserSshPaths()
    {
        var result = new List<string>();
        try
        {
            if (Directory.Exists("/home"))
            {
                foreach (var homeDir in Directory.GetDirectories("/home"))
                {
                    var sshDir = System.IO.Path.Combine(homeDir, ".ssh");
                    if (Directory.Exists(sshDir))
                    {
                        result.Add(sshDir);
                        var authKeys = System.IO.Path.Combine(sshDir, "authorized_keys");
                        if (File.Exists(authKeys))
                            result.Add(authKeys);
                    }
                }
            }
        }
        catch
        {
            // Ignore enumeration errors
        }
        return result;
    }

    private static async Task ScanPathsAsync(List<string> paths, ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var args = new List<string> { "-c", "%a %U %G %n" };
        args.AddRange(paths);

        var (stdout, stderr, success) = await RunCommandAsync("stat", args.ToArray(), cancellationToken);
        var status = DataSourceCapability.FromCommandResult(success, stdout, stderr);

        if (!string.IsNullOrWhiteSpace(stderr) && DataSourceCapability.ContainsPermissionDenied(stderr))
        {
            status = CapabilityStatus.PermissionLimited;
        }

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "stat",
            Status = status,
            Detail = stderr
        });

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var entry = ParseStatLine(line.Trim());
                if (entry != null)
                    builder.AddFilePermission(entry);
            }
        }

        if (!success && status != CapabilityStatus.PermissionLimited)
        {
            builder.AddWarning($"File permission scan partially failed: {stderr}".Trim());
        }
    }

    internal static FilePermissionEntry? ParseStatLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        // Format: %a %U %G %n  ->  640 root shadow /etc/shadow
        var parts = line.Split(' ', 4);
        if (parts.Length < 4)
            return null;

        var mode = parts[0].Trim();
        var owner = parts[1].Trim();
        var group = parts[2].Trim();
        var path = parts[3].Trim();

        if (string.IsNullOrEmpty(path))
            return null;

        return new FilePermissionEntry
        {
            Path = path,
            Mode = mode,
            Owner = owner,
            Group = group,
            Exists = true
        };
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
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

            await using (ct.Register(() =>
            {
                try { process.Kill(); } catch { /* ignore */ }
            }))
            {
                var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
                var stderrTask = process.StandardError.ReadToEndAsync(ct);
                var exitTask = process.WaitForExitAsync(ct);
                await Task.WhenAll(stdoutTask, stderrTask, exitTask);
                var success = process.ExitCode == 0;
                return (stdoutTask.Result, stderrTask.Result, success);
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
}
