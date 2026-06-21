namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans kernel and system hardening parameters from /proc/sys, sysctl, and EFI variables.
/// </summary>
public sealed class KernelHardeningScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "KernelHardening";

    private static readonly string[] ProcSysPaths =
    {
        "/proc/sys/kernel/randomize_va_space",
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
        "/proc/sys/net/ipv4/conf/all/accept_redirects",
        "/proc/sys/net/ipv6/conf/all/accept_redirects",
        "/proc/sys/net/ipv4/conf/all/accept_source_route",
        "/proc/sys/kernel/modules_disabled",
        "/proc/sys/kernel/kptr_restrict",
        "/proc/sys/kernel/dmesg_restrict"
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var values = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        bool anyRead = false;
        string? firstError = null;

        foreach (var path in ProcSysPaths)
        {
            try
            {
                if (File.Exists(path))
                {
                    var text = await File.ReadAllTextAsync(path, cancellationToken);
                    var trimmed = text.Trim();
                    if (int.TryParse(trimmed, out var num))
                    {
                        values[path] = num;
                        anyRead = true;
                    }
                }
            }
            catch (Exception ex)
            {
                firstError ??= ex.Message;
            }
        }

        // Fallback: use sysctl -a for any missing values (helps on systems where /proc/sys files differ)
        if (values.Count < ProcSysPaths.Length)
        {
            var (stdout, stderr, ok) = await RunCommandAsync("sysctl", new[] { "-a" }, cancellationToken);
            var status = DataSourceCapability.FromCommandResult(ok, stdout, stderr);
            builder.AddCapability(new DataSourceCapability { SourceName = "sysctl -a", Status = status, Detail = stderr, Command = "sysctl -a" });

            if (ok && !string.IsNullOrWhiteSpace(stdout))
            {
                foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var kv = ParseSysctlLine(line);
                    if (kv.HasValue)
                    {
                        var procPath = SysctlKeyToProcPath(kv.Value.Key);
                        if (!values.ContainsKey(procPath) && int.TryParse(kv.Value.Value, out var num))
                        {
                            values[procPath] = num;
                        }
                    }
                }
            }
        }
        else
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "sysctl -a", Status = CapabilityStatus.Available, Detail = "Values already read from /proc/sys", Command = "sysctl -a" });
        }

        // Secure Boot check
        bool? secureBoot = await CheckSecureBootAsync(cancellationToken);

        var parameters = new KernelParameters
        {
            ParametersReadable = anyRead,
            ReadWarning = firstError,
            RandomizeVaSpace = GetValue(values, "/proc/sys/kernel/randomize_va_space"),
            IpForwardIpv4 = GetValue(values, "/proc/sys/net/ipv4/ip_forward"),
            IpForwardIpv6 = GetValue(values, "/proc/sys/net/ipv6/conf/all/forwarding"),
            AcceptRedirectsIpv4 = GetValue(values, "/proc/sys/net/ipv4/conf/all/accept_redirects"),
            AcceptRedirectsIpv6 = GetValue(values, "/proc/sys/net/ipv6/conf/all/accept_redirects"),
            AcceptSourceRouteIpv4 = GetValue(values, "/proc/sys/net/ipv4/conf/all/accept_source_route"),
            ModulesDisabled = GetValue(values, "/proc/sys/kernel/modules_disabled"),
            KptrRestrict = GetValue(values, "/proc/sys/kernel/kptr_restrict"),
            DmesgRestrict = GetValue(values, "/proc/sys/kernel/dmesg_restrict"),
            SecureBootEnabled = secureBoot
        };

        builder.SetKernelParameters(parameters);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "/proc/sys",
            Status = anyRead ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = firstError,
            Command = "/proc/sys/*"
        });

        if (secureBoot.HasValue)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "secureboot",
                Status = CapabilityStatus.Available,
                Command = "mokutil --sb-state"
            });
        }
        else
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "secureboot",
                Status = CapabilityStatus.Unavailable,
                Detail = "Could not determine Secure Boot status (mokutil or efivars unavailable)",
                Command = "mokutil --sb-state"
            });
        }
    }

    internal static KeyValuePair<string, string>? ParseSysctlLine(string line)
    {
        line = line.Trim();
        if (string.IsNullOrWhiteSpace(line))
            return null;

        var eqIndex = line.IndexOf('=');
        if (eqIndex <= 0)
            return null;

        var key = line.Substring(0, eqIndex).Trim();
        var value = line.Substring(eqIndex + 1).Trim();
        return new KeyValuePair<string, string>(key, value);
    }

    internal static string SysctlKeyToProcPath(string key)
    {
        return "/proc/sys/" + key.Replace('.', '/');
    }

    private static int? GetValue(Dictionary<string, int> values, string path)
    {
        return values.TryGetValue(path, out var value) ? value : null;
    }

    private static async Task<bool?> CheckSecureBootAsync(CancellationToken ct)
    {
        // Prefer mokutil when available
        var (stdout, stderr, ok) = await RunCommandAsync("mokutil", new[] { "--sb-state" }, ct);
        if (ok && !string.IsNullOrWhiteSpace(stdout))
        {
            if (stdout.Contains("SecureBoot enabled", StringComparison.OrdinalIgnoreCase))
                return true;
            if (stdout.Contains("SecureBoot disabled", StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // Fallback: read EFI variable directly
        try
        {
            var efivarDir = "/sys/firmware/efi/efivars";
            if (Directory.Exists(efivarDir))
            {
                var secureBootFile = Directory.GetFiles(efivarDir, "SecureBoot-*").FirstOrDefault();
                if (secureBootFile != null && File.Exists(secureBootFile))
                {
                    // EFI variable files have a 4-byte attribute prefix followed by the data
                    await using var fs = new FileStream(secureBootFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                    var buffer = new byte[8];
                    var read = await fs.ReadAsync(buffer.AsMemory(0, 8), ct);
                    if (read >= 5)
                    {
                        // byte[4] is the SecureBoot value: 1 = enabled, 0 = disabled
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

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
