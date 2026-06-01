using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans system and user crontabs as well as cron script directories for scheduled job entries.
/// </summary>
public sealed class CronJobScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "CronJob";

    private static readonly string[] SystemCrontabPaths =
    {
        "/etc/crontab"
    };

    private static readonly string[] CronDPaths =
    {
        "/etc/cron.d"
    };

    private static readonly string[] UserCrontabPaths =
    {
        "/var/spool/cron/crontabs",
        "/var/spool/cron"
    };

    private static readonly (string Directory, string Schedule)[] ScriptDirectories =
    {
        ("/etc/cron.daily", "@daily"),
        ("/etc/cron.hourly", "@hourly"),
        ("/etc/cron.weekly", "@weekly"),
        ("/etc/cron.monthly", "@monthly")
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        foreach (var path in SystemCrontabPaths)
        {
            await ScanCrontabAsync(path, isSystemCrontab: true, builder, cancellationToken);
        }

        foreach (var path in CronDPaths)
        {
            await ScanCronDAsync(path, builder, cancellationToken);
        }

        foreach (var path in UserCrontabPaths)
        {
            await ScanUserCrontabsAsync(path, builder, cancellationToken);
        }

        foreach (var (directory, schedule) in ScriptDirectories)
        {
            await ScanScriptDirectoryAsync(directory, schedule, builder, cancellationToken);
        }
    }

    private static async Task ScanCrontabAsync(string path, bool isSystemCrontab, ScanDataBuilder builder, CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = path,
                Status = CapabilityStatus.Unavailable,
                Detail = $"{path} not found."
            });
            return;
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(path, ct);
            var entries = ParseCrontabLines(lines, path, isSystemCrontab);
            foreach (var entry in entries)
            {
                builder.AddCronJob(entry);
            }

            builder.AddCapability(new DataSourceCapability
            {
                SourceName = path,
                Status = CapabilityStatus.Available
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = path,
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    private static async Task ScanCronDAsync(string directory, ScanDataBuilder builder, CancellationToken ct)
    {
        if (!Directory.Exists(directory))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = $"{directory} not found."
            });
            return;
        }

        try
        {
            var files = Directory.GetFiles(directory);
            var anyFound = false;
            foreach (var file in files)
            {
                anyFound = true;
                await ScanCrontabAsync(file, isSystemCrontab: true, builder, ct);
            }

            if (!anyFound)
            {
                builder.AddCapability(new DataSourceCapability
                {
                    SourceName = directory,
                    Status = CapabilityStatus.Available,
                    Detail = "No files found in cron.d."
                });
            }
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    private static async Task ScanUserCrontabsAsync(string directory, ScanDataBuilder builder, CancellationToken ct)
    {
        if (!Directory.Exists(directory))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = $"{directory} not found."
            });
            return;
        }

        try
        {
            var files = Directory.GetFiles(directory);
            var anyFound = false;
            foreach (var file in files)
            {
                anyFound = true;
                await ScanCrontabAsync(file, isSystemCrontab: false, builder, ct);
            }

            if (!anyFound)
            {
                builder.AddCapability(new DataSourceCapability
                {
                    SourceName = directory,
                    Status = CapabilityStatus.Available,
                    Detail = "No user crontabs found."
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.PermissionLimited,
                Detail = "Permission denied reading user crontabs (requires root)."
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    private static async Task ScanScriptDirectoryAsync(string directory, string schedule, ScanDataBuilder builder, CancellationToken ct)
    {
        if (!Directory.Exists(directory))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = $"{directory} not found."
            });
            return;
        }

        try
        {
            var files = Directory.GetFiles(directory);
            if (files.Length == 0)
            {
                builder.AddCapability(new DataSourceCapability
                {
                    SourceName = directory,
                    Status = CapabilityStatus.Available,
                    Detail = "No scripts found."
                });
                return;
            }

            // Batch stat all files for permissions
            var statEntries = await StatFilesAsync(files, ct);

            foreach (var file in files)
            {
                var entry = new CronJobEntry
                {
                    SourceFile = file,
                    Schedule = schedule,
                    Command = file,
                    IsScript = true
                };

                if (statEntries.TryGetValue(file, out var stat))
                {
                    entry = entry with
                    {
                        ScriptPermissions = stat.Mode,
                        ScriptOwner = stat.Owner,
                        ScriptGroup = stat.Group
                    };
                }

                builder.AddCronJob(entry);
            }

            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Available
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = directory,
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    internal static List<CronJobEntry> ParseCrontabLines(string[] lines, string sourceFile, bool isSystemCrontab)
    {
        var entries = new List<CronJobEntry>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            // Skip empty lines and comments
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                continue;

            // Skip environment variable lines (contain = before any schedule-like token)
            if (IsEnvironmentVariableLine(line))
                continue;

            var entry = ParseCronLine(line, sourceFile, isSystemCrontab);
            if (entry != null)
                entries.Add(entry);
        }

        return entries;
    }

    internal static bool IsEnvironmentVariableLine(string line)
    {
        // Environment lines look like: SHELL=/bin/bash, PATH=/usr/bin, MAILTO=""
        // We check if there's an = before the first token that looks like a schedule field
        var eqIndex = line.IndexOf('=');
        if (eqIndex < 0)
            return false;

        var beforeEq = line.Substring(0, eqIndex).Trim();
        // If before the = there's no space and it's not a schedule token, it's likely an env var
        if (!beforeEq.Contains(' ') && !LooksLikeScheduleField(beforeEq))
            return true;

        return false;
    }

    private static bool LooksLikeScheduleField(string token)
    {
        if (string.IsNullOrEmpty(token))
            return false;

        // Special schedules: @reboot, @yearly, etc.
        if (token.StartsWith('@'))
            return true;

        // Standard cron fields contain digits, *, -, ,, /
        return token.All(c => char.IsDigit(c) || c is '*' or '-' or ',' or '/');
    }

    internal static CronJobEntry? ParseCronLine(string line, string sourceFile, bool isSystemCrontab)
    {
        var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return null;

        // Check for special schedule (@reboot, @yearly, etc.) — single token schedule
        string schedule;
        int commandStartIndex;

        if (parts[0].StartsWith('@'))
        {
            if (parts.Length < 2)
                return null;

            schedule = parts[0];
            commandStartIndex = 1;
        }
        else
        {
            // Need at least 5 schedule fields
            if (parts.Length < 6)
                return null;

            // Verify first 5 fields look like schedule fields
            for (int i = 0; i < 5; i++)
            {
                if (!LooksLikeScheduleField(parts[i]))
                    return null;
            }

            schedule = string.Join(" ", parts.Take(5));
            commandStartIndex = 5;
        }

        string? runAsUser = null;

        if (isSystemCrontab)
        {
            // For system crontabs, the next field after schedule is the user
            if (parts.Length <= commandStartIndex)
                return null;

            runAsUser = parts[commandStartIndex];
            commandStartIndex++;
        }

        if (parts.Length <= commandStartIndex)
            return null;

        var command = string.Join(" ", parts.Skip(commandStartIndex));

        return new CronJobEntry
        {
            SourceFile = sourceFile,
            Schedule = schedule,
            Command = command,
            RunAsUser = runAsUser,
            IsScript = false
        };
    }

    private static async Task<Dictionary<string, FilePermissionEntry>> StatFilesAsync(string[] files, CancellationToken ct)
    {
        var result = new Dictionary<string, FilePermissionEntry>(StringComparer.Ordinal);

        if (files.Length == 0)
            return result;

        var args = new List<string> { "-c", "%a %U %G %n" };
        args.AddRange(files);

        var (stdout, _, success) = await RunCommandAsync("stat", args.ToArray(), ct);

        if (!success || string.IsNullOrWhiteSpace(stdout))
            return result;

        foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var entry = FilePermissionScanner.ParseStatLine(line.Trim());
            if (entry != null)
            {
                result[entry.Path] = entry;
            }
        }

        return result;
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
