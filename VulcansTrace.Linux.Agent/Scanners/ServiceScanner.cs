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

        var status = DataSourceCapability.FromCommandResult(ok, output, error);
        builder.AddCapability(new DataSourceCapability { SourceName = "systemctl", Status = status, Detail = error, Command = "systemctl list-units --type=service --state=running --no-pager --no-legend" });

        if (status == CapabilityStatus.PermissionLimited)
        {
            builder.AddWarning("Service scan skipped: permission denied.");
            return;
        }

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
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
