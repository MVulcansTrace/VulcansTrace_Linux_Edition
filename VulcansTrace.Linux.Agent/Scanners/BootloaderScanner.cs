namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans boot loader configuration: GRUB defaults, current kernel cmdline, and Secure Boot status.
/// </summary>
public sealed class BootloaderScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Bootloader";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var config = await ScanAsync("/etc/default/grub", "/etc/grub.d", cancellationToken);
        builder.SetBootloaderConfig(config);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "bootloader",
            Status = config.ConfigReadable ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = config.ReadWarning,
            Command = "cat /etc/default/grub; cat /proc/cmdline; mokutil --sb-state"
        });
    }

    internal static Task<BootloaderConfig> ScanAsync(string grubPath, CancellationToken ct) =>
        ScanAsync(grubPath, "/etc/grub.d", ct);

    internal static async Task<BootloaderConfig> ScanAsync(string grubPath, string grubDirectoryPath, CancellationToken ct)
    {
        bool grubExists = File.Exists(grubPath);
        var grubVariables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? grubWarning = null;

        if (grubExists)
        {
            try
            {
                var lines = await File.ReadAllLinesAsync(grubPath, ct);
                foreach (var rawLine in lines)
                {
                    var line = rawLine.Trim();
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                        continue;

                    var eqIndex = line.IndexOf('=');
                    if (eqIndex <= 0)
                        continue;

                    var key = line.Substring(0, eqIndex).Trim();
                    var value = line.Substring(eqIndex + 1).Trim();

                    // Strip matching quotes
                    if (value.Length >= 2 && ((value[0] == '\"' && value[^1] == '\"') || (value[0] == '\'' && value[^1] == '\'')))
                    {
                        value = value[1..^1];
                    }

                    grubVariables[key] = value;
                }
            }
            catch (Exception ex)
            {
                grubWarning = ex.Message;
            }
        }

        string cmdline = string.Empty;
        try
        {
            if (File.Exists("/proc/cmdline"))
            {
                cmdline = await File.ReadAllTextAsync("/proc/cmdline", ct);
                cmdline = cmdline.Trim();
            }
        }
        catch (Exception ex)
        {
            grubWarning ??= ex.Message;
        }

        bool? secureBoot = await CheckSecureBootAsync(ct);
        var grubPasswordConfigured = HasPasswordConfiguration(grubVariables) ||
                                     await GrubDirectoryHasPasswordConfigurationAsync(grubDirectoryPath, ct);

        var readable = grubExists || !string.IsNullOrWhiteSpace(cmdline);

        return new BootloaderConfig
        {
            ConfigReadable = readable,
            GrubFileExists = grubExists,
            GrubVariables = grubVariables,
            GrubPasswordConfigured = grubPasswordConfigured,
            KernelCmdline = cmdline,
            SecureBootEnabled = secureBoot,
            ReadWarning = readable ? null : grubWarning ?? "Could not read GRUB configuration or kernel command line."
        };
    }

    internal static bool HasPasswordConfiguration(IReadOnlyDictionary<string, string> grubVariables)
    {
        return grubVariables.Keys.Any(k =>
            k.Contains("PASSWORD", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("SUPERUSERS", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<bool> GrubDirectoryHasPasswordConfigurationAsync(string grubDirectoryPath, CancellationToken ct)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(grubDirectoryPath) || !Directory.Exists(grubDirectoryPath))
                return false;

            foreach (var file in Directory.EnumerateFiles(grubDirectoryPath))
            {
                ct.ThrowIfCancellationRequested();
                var text = await File.ReadAllTextAsync(file, ct);
                if (text.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("superuser", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Ignore unreadable GRUB helper scripts; the rule remains based on collected data.
        }

        return false;
    }

    internal static async Task<bool?> CheckSecureBootAsync(CancellationToken ct)
    {
        var (stdout, _, ok) = await RunCommandAsync("mokutil", new[] { "--sb-state" }, ct);
        if (ok && !string.IsNullOrWhiteSpace(stdout))
        {
            if (stdout.Contains("SecureBoot enabled", StringComparison.OrdinalIgnoreCase))
                return true;
            if (stdout.Contains("SecureBoot disabled", StringComparison.OrdinalIgnoreCase))
                return false;
        }

        try
        {
            var efivarDir = "/sys/firmware/efi/efivars";
            if (Directory.Exists(efivarDir))
            {
                var secureBootFile = Directory.GetFiles(efivarDir, "SecureBoot-*").FirstOrDefault();
                if (secureBootFile != null && File.Exists(secureBootFile))
                {
                    await using var fs = new FileStream(secureBootFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                    var buffer = new byte[8];
                    var read = await fs.ReadAsync(buffer.AsMemory(0, 8), ct);
                    if (read >= 5)
                    {
                        return buffer[4] != 0;
                    }
                }
            }
        }
        catch
        {
            // Ignore — Secure Boot may be unavailable on BIOS systems
        }

        return null;
    }

    internal static bool CmdlineContains(string cmdline, string parameter)
    {
        if (string.IsNullOrWhiteSpace(cmdline))
            return false;

        return cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Any(token => token.Equals(parameter, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool CmdlineContainsPattern(string cmdline, string prefix)
    {
        if (string.IsNullOrWhiteSpace(cmdline))
            return false;

        return cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Any(token => token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    internal static string? CmdlineParameterValue(string cmdline, string parameter)
    {
        if (string.IsNullOrWhiteSpace(cmdline) || string.IsNullOrWhiteSpace(parameter))
            return null;

        var prefix = parameter.EndsWith("=", StringComparison.Ordinal) ? parameter : parameter + "=";
        foreach (var token in cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return token.Substring(prefix.Length);
        }

        return null;
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
