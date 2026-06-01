using System.Diagnostics;
using System.Text;

namespace VulcansTrace.Linux.Agent.Scheduling;

/// <summary>
/// Manages user crontab entries for VulcansTrace scheduled audits.
/// </summary>
public sealed class CrontabManager
{
    /// <summary>
    /// Unique marker prefix to avoid collision with non-VulcansTrace entries.
    /// Contains a UUID-like segment that is extremely unlikely to collide.
    /// </summary>
    private const string MarkerPrefix = "# VT-SCH-7a3f9e2d schedule-id=";

    /// <summary>
    /// Gets the current vulcanstrace executable path used in cron entries.
    /// Defaults to <c>vulcanstrace</c> if running under <c>dotnet</c>.
    /// </summary>
    public static string DefaultExePath
    {
        get
        {
            var processPath = Environment.ProcessPath ?? "vulcanstrace";
            var fileName = Path.GetFileNameWithoutExtension(processPath);
            return string.Equals(fileName, "dotnet", StringComparison.OrdinalIgnoreCase)
                ? "vulcanstrace"
                : processPath;
        }
    }

    /// <summary>
    /// Reads the current user crontab.
    /// </summary>
    /// <returns>The raw crontab content, or empty string if none exists.</returns>
    public static string ReadCrontab()
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "crontab",
                ArgumentList = { "-l" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo)!;
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            // crontab -l returns exit code 1 when there is no crontab.
            // Different cron implementations emit different messages, so we
            // treat exit code 1 with empty/whitespace output as "no crontab".
            if (process.ExitCode != 0)
            {
                var combined = (output + error).Trim();
                var isEmptyCrontab = string.IsNullOrWhiteSpace(combined)
                    || combined.Contains("no crontab", StringComparison.OrdinalIgnoreCase)
                    || combined.Contains("no entries", StringComparison.OrdinalIgnoreCase);

                if (!isEmptyCrontab)
                {
                    throw new InvalidOperationException($"crontab -l failed: {error}");
                }
            }

            return output;
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException($"Failed to read crontab: {ex.Message}");
        }
    }

    /// <summary>
    /// Writes the user crontab.
    /// </summary>
    /// <param name="content">The new crontab content.</param>
    public static void WriteCrontab(string content)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "crontab",
                ArgumentList = { "-" },
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo)!;
            process.StandardInput.Write(content);
            process.StandardInput.Close();

            // Read stderr asynchronously to avoid deadlock if the buffer fills (>4KB)
            var stderrTask = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            var error = stderrTask.GetAwaiter().GetResult();

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"crontab write failed: {error}");
            }
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException($"Failed to write crontab: {ex.Message}");
        }
    }

    /// <summary>
    /// Returns the IDs of all VulcansTrace schedules currently installed in the crontab.
    /// </summary>
    public static IReadOnlyList<string> GetInstalledScheduleIds()
    {
        try
        {
            var crontab = ReadCrontab();
            var lines = crontab.Split('\n');
            var ids = new List<string>();

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith(MarkerPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    var id = trimmed[MarkerPrefix.Length..].Trim();
                    if (!string.IsNullOrWhiteSpace(id))
                        ids.Add(id);
                }
            }

            return ids;
        }
        catch (InvalidOperationException)
        {
            // crontab binary unavailable — treat as no installed schedules
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// Installs a cron entry for the specified schedule.
    /// </summary>
    /// <param name="schedule">The schedule to install.</param>
    /// <param name="exePath">Path to the vulcanstrace executable. Defaults to <see cref="DefaultExePath"/>.</param>
    /// <exception cref="InvalidOperationException">Thrown if the schedule is disabled.</exception>
    public static void Install(AuditSchedule schedule, string? exePath = null)
    {
        ArgumentNullException.ThrowIfNull(schedule);

        if (!schedule.Enabled)
        {
            throw new InvalidOperationException($"Cannot install disabled schedule '{schedule.Name}'. Enable it first.");
        }

        var path = exePath ?? DefaultExePath;
        var crontab = ReadCrontab();
        var lines = crontab.Split('\n').ToList();

        // Remove any existing entry for this schedule
        RemoveLinesForSchedule(lines, schedule.Id);

        lines.Add($"{MarkerPrefix}{schedule.Id}");
        lines.Add($"{schedule.CronExpression} {BuildRunCommand(path, schedule.Id)}");

        // Remove trailing blank lines, then add exactly one
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[^1]))
        {
            lines.RemoveAt(lines.Count - 1);
        }
        lines.Add("");

        WriteCrontab(string.Join('\n', lines));
    }

    /// <summary>
    /// Removes the cron entry for the specified schedule ID.
    /// </summary>
    /// <param name="scheduleId">The schedule ID to uninstall.</param>
    public static void Uninstall(string scheduleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheduleId);

        var crontab = ReadCrontab();
        var lines = crontab.Split('\n').ToList();

        if (!RemoveLinesForSchedule(lines, scheduleId))
        {
            throw new InvalidOperationException($"No crontab entry found for schedule {scheduleId}.");
        }

        // Remove trailing blank lines, then add exactly one
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[^1]))
        {
            lines.RemoveAt(lines.Count - 1);
        }
        lines.Add("");

        WriteCrontab(string.Join('\n', lines));
    }

    /// <summary>
    /// Returns whether a crontab entry exists for the given schedule ID.
    /// </summary>
    public static bool IsInstalled(string scheduleId)
    {
        return GetInstalledScheduleIds().Any(id => id.Equals(scheduleId, StringComparison.OrdinalIgnoreCase));
    }

    private static bool RemoveLinesForSchedule(List<string> lines, string scheduleId)
    {
        var removed = false;
        for (var i = lines.Count - 1; i >= 0; i--)
        {
            var trimmed = lines[i].Trim();
            // Remove the marker comment
            if (trimmed.StartsWith(MarkerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                var id = trimmed[MarkerPrefix.Length..].Trim();
                if (id.Equals(scheduleId, StringComparison.OrdinalIgnoreCase))
                {
                    lines.RemoveAt(i);
                    removed = true;

                    if (i < lines.Count && IsScheduleRunCommand(lines[i], scheduleId))
                    {
                        lines.RemoveAt(i);
                    }
                }
            }
            // Independently remove the command line that references this schedule id
            else if (IsScheduleRunCommand(trimmed, scheduleId))
            {
                lines.RemoveAt(i);
                removed = true;
            }
        }
        return removed;
    }

    public static string BuildRunCommand(string exePath, string scheduleId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(exePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheduleId);

        return $"{ShellQuote(exePath)} schedule run --id {ShellQuote(scheduleId)}";
    }

    private static bool IsScheduleRunCommand(string line, string scheduleId)
    {
        var trimmed = line.Trim();
        return trimmed.Contains($" schedule run --id {scheduleId}", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains($" schedule run --id {ShellQuote(scheduleId)}", StringComparison.OrdinalIgnoreCase);
    }

    private static string ShellQuote(string value)
    {
        return $"'{value.Replace("'", "'\\''", StringComparison.Ordinal)}'";
    }
}
