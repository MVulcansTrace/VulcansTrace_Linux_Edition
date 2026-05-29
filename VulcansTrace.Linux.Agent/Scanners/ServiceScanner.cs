using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans for running system services using <c>systemctl</c>.
/// </summary>
public sealed class ServiceScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Service";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var (output, error, ok) = await RunCommandAsync("systemctl", new[]
        {
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend"
        }, cancellationToken);

        if (!ok || string.IsNullOrWhiteSpace(output))
        {
            builder.AddWarning($"Service scan skipped: 'systemctl' is not available (non-systemd system?). {error}");
            return;
        }

        ParseOutput(output, builder);
    }

    internal static void ParseOutput(string output, ScanDataBuilder builder)
    {
        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Format: UNIT LOAD ACTIVE SUB DESCRIPTION
            // e.g., "sshd.service loaded active running OpenSSH server daemon"
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                continue;

            var unitName = parts[0];
            var loadState = parts[1];
            var activeState = parts[2];
            var subState = parts[3];
            var description = parts.Length > 4 ? string.Join(" ", parts.Skip(4)) : unitName;

            builder.AddRunningService(new RunningService
            {
                Name = unitName,
                State = $"{activeState}/{subState}",
                Description = description
            });
        }
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
