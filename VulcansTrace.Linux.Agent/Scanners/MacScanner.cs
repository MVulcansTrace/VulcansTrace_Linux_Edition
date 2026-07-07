using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans mandatory access control status: AppArmor and SELinux.
/// </summary>
public sealed class MacScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Mac";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var config = await ScanAsync(cancellationToken);
        builder.SetMacConfig(config);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "mac",
            Status = config.ConfigReadable ? CapabilityStatus.Available : CapabilityStatus.Unavailable,
            Detail = config.ReadWarning,
            Command = "aa-status; getenforce; cat /etc/selinux/config"
        });
    }

    internal static async Task<MacConfig> ScanAsync(CancellationToken ct)
    {
        var appArmorInstalled = Directory.Exists("/sys/module/apparmor") ||
                                File.Exists("/sbin/apparmor_parser") ||
                                File.Exists("/usr/sbin/aa-status");

        bool appArmorEnforcing = false;
        bool? appArmorEnabled = null;
        string? appArmorMode = null;
        var complainProfiles = new List<string>();
        var enforceProfiles = new List<string>();
        var unconfined = new List<string>();

        if (appArmorInstalled)
        {
            appArmorEnabled = ParseAppArmorEnabledValue(
                await TryReadTrimmedFileAsync("/sys/module/apparmor/parameters/enabled", ct));
            appArmorMode = await TryReadTrimmedFileAsync("/sys/module/apparmor/parameters/mode", ct);

            var (aaOutput, aaError, aaOk) = await RunCommandAsync("aa-status", Array.Empty<string>(), ct);
            var aaStatusText = CombineOutput(aaOutput, aaError);
            if ((aaOk || !string.IsNullOrWhiteSpace(aaStatusText)) && !string.IsNullOrWhiteSpace(aaStatusText))
            {
                if (aaStatusText.Contains("apparmor module is loaded", StringComparison.OrdinalIgnoreCase))
                    appArmorInstalled = true;

                ParseAppArmorStatus(aaStatusText, complainProfiles, enforceProfiles, unconfined);
            }

            var enabled = appArmorEnabled.GetValueOrDefault(true);
            var globalComplain = appArmorMode?.Trim().Equals("complain", StringComparison.OrdinalIgnoreCase) == true;
            var statusReportsEnforceProfiles = AppArmorStatusReportsProfilesInMode(aaStatusText, "enforce");
            var modeReportsEnforcing = appArmorMode?.Trim().Equals("enforce", StringComparison.OrdinalIgnoreCase) == true;

            appArmorEnforcing = enabled &&
                                !globalComplain &&
                                (enforceProfiles.Count > 0 || statusReportsEnforceProfiles || modeReportsEnforcing);
        }

        bool selinuxInstalled = Directory.Exists("/sys/fs/selinux") ||
                                File.Exists("/usr/sbin/getenforce") ||
                                File.Exists("/sbin/getenforce");
        var selinuxMode = "disabled";

        if (selinuxInstalled)
        {
            var (modeOutput, _, modeOk) = await RunCommandAsync("getenforce", Array.Empty<string>(), ct);
            if (modeOk && !string.IsNullOrWhiteSpace(modeOutput))
            {
                selinuxMode = modeOutput.Trim().ToLowerInvariant();
            }
            else
            {
                // Fallback to config file
                selinuxMode = ReadSelinuxConfigMode();
            }
        }

        var readable = appArmorInstalled || selinuxInstalled;

        return new MacConfig
        {
            ConfigReadable = readable,
            AppArmorInstalled = appArmorInstalled,
            AppArmorEnforcing = appArmorEnforcing,
            AppArmorComplainProfiles = complainProfiles,
            AppArmorEnforceProfiles = enforceProfiles,
            AppArmorUnconfined = unconfined,
            SelinuxInstalled = selinuxInstalled,
            SelinuxMode = selinuxMode,
            ReadWarning = readable ? null : "Neither AppArmor nor SELinux appear to be installed."
        };
    }

    internal static bool? ParseAppArmorEnabledValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        if (normalized.Equals("Y", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("1", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("true", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("enabled", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (normalized.Equals("N", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("0", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("no", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("false", StringComparison.OrdinalIgnoreCase) ||
            normalized.Equals("disabled", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return null;
    }

    internal static bool AppArmorStatusReportsProfilesInMode(string? output, string mode)
    {
        if (string.IsNullOrWhiteSpace(output) || string.IsNullOrWhiteSpace(mode))
            return false;

        var pattern = @"^\s*(\d+)\s+profiles\s+are\s+in\s+" +
                      Regex.Escape(mode) +
                      @"\s+mode\.?\s*$";
        foreach (var rawLine in output.Split('\n'))
        {
            var match = Regex.Match(rawLine, pattern, RegexOptions.IgnoreCase);
            if (match.Success &&
                int.TryParse(match.Groups[1].Value, out var count) &&
                count > 0)
            {
                return true;
            }
        }

        return false;
    }

    internal static void ParseAppArmorStatus(
        string output,
        List<string> complainProfiles,
        List<string> enforceProfiles,
        List<string> unconfined)
    {
        string? currentSection = null;

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Every count line ("N profiles ...", "M processes ...") starts with a digit.
            // The process-section summaries that follow "processes have profiles defined."
            // (e.g. "2 processes are in enforce mode.") are NOT profiles and must not be
            // collected; only the "processes are unconfined ..." line opens the real list.
            if (line.Length > 0 && char.IsDigit(line[0]) &&
                line.Contains("processes", StringComparison.OrdinalIgnoreCase))
            {
                if (line.Contains("unconfined", StringComparison.OrdinalIgnoreCase))
                    currentSection = "unconfined";
                // Per-mode process counts otherwise leave the section untouched.
                continue;
            }

            // Profile-mode section headers.
            if (line.Contains("profiles are in complain mode", StringComparison.OrdinalIgnoreCase))
            {
                currentSection = "complain";
                continue;
            }
            if (line.Contains("profiles are in enforce mode", StringComparison.OrdinalIgnoreCase))
            {
                currentSection = "enforce";
                continue;
            }

            // Top-of-output status / loaded-count lines reset context.
            if (line.Contains("profiles are loaded", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("AppArmor", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("apparmor module", StringComparison.OrdinalIgnoreCase))
            {
                currentSection = null;
                continue;
            }

            // Profile entries may carry an explicit trailing mode suffix.
            if (line.EndsWith("(complain)", StringComparison.OrdinalIgnoreCase))
            {
                complainProfiles.Add(line.Substring(0, line.Length - "(complain)".Length).Trim(' ', '\t', '\r', '*'));
                continue;
            }
            if (line.EndsWith("(enforce)", StringComparison.OrdinalIgnoreCase))
            {
                enforceProfiles.Add(line.Substring(0, line.Length - "(enforce)".Length).Trim(' ', '\t', '\r', '*'));
                continue;
            }

            // Otherwise bucket by the active section.
            var cleaned = line.Trim(' ', '\t', '\r', '*');
            if (cleaned.Length == 0)
                continue;

            if (currentSection == "complain")
                complainProfiles.Add(cleaned);
            else if (currentSection == "enforce")
                enforceProfiles.Add(cleaned);
            else if (currentSection == "unconfined")
                unconfined.Add(cleaned);
        }
    }

    internal static string ReadSelinuxConfigMode(string? path = null)
    {
        path ??= "/etc/selinux/config";
        if (!File.Exists(path))
            return "disabled";

        try
        {
            foreach (var rawLine in File.ReadAllLines(path))
            {
                var line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;

                if (line.StartsWith("SELINUX=", StringComparison.OrdinalIgnoreCase))
                {
                    return line.Substring("SELINUX=".Length).Trim().ToLowerInvariant();
                }
            }
        }
        catch
        {
            // Ignore
        }

        return "disabled";
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }

    private static async Task<string?> TryReadTrimmedFileAsync(string path, CancellationToken ct)
    {
        try
        {
            if (!File.Exists(path))
                return null;

            return (await File.ReadAllTextAsync(path, ct)).Trim();
        }
        catch
        {
            return null;
        }
    }

    private static string CombineOutput(string? stdout, string? stderr)
    {
        if (string.IsNullOrWhiteSpace(stdout))
            return stderr?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(stderr))
            return stdout.Trim();
        return stdout.Trim() + Environment.NewLine + stderr.Trim();
    }
}
