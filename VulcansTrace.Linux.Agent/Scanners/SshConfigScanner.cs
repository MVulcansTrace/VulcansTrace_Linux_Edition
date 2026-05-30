using System.Diagnostics;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans SSH daemon configuration from <c>/etc/ssh/sshd_config</c> and included files.
/// </summary>
public sealed class SshConfigScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "SshConfig";

    private static readonly string[] ConfigPaths =
    {
        "/etc/ssh/sshd_config",
        "/usr/local/etc/ssh/sshd_config",
        "/etc/sshd_config"
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        // Prefer sshd -T when available because it resolves includes and defaults.
        var (testOutput, testError, testOk) = await RunCommandAsync("sshd", new[] { "-T" }, cancellationToken);
        var testStatus = DataSourceCapability.FromCommandResult(testOk, testOutput, testError);
        builder.AddCapability(new DataSourceCapability { SourceName = "sshd -T", Status = testStatus, Detail = testError });

        if (testOk && !string.IsNullOrWhiteSpace(testOutput))
        {
            var config = ParseSshdTOutput(testOutput);
            builder.SetSshConfig(config);
            return;
        }

        // Fallback: read config files directly.
        string? configPath = null;
        foreach (var path in ConfigPaths)
        {
            if (File.Exists(path))
            {
                configPath = path;
                break;
            }
        }

        if (configPath == null)
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "sshd_config", Status = CapabilityStatus.Unavailable, Detail = "No sshd_config found" });
            builder.AddWarning("SSH config scan skipped: no sshd_config found.");
            return;
        }

        try
        {
            var content = await File.ReadAllTextAsync(configPath, cancellationToken);
            var config = ParseConfigFile(content, configPath);
            builder.SetSshConfig(config);
            builder.AddCapability(new DataSourceCapability { SourceName = "sshd_config", Status = CapabilityStatus.Available });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "sshd_config", Status = CapabilityStatus.Unavailable, Detail = ex.Message });
            builder.AddWarning($"SSH config scan skipped: failed to read {configPath}. {ex.Message}");
        }
    }

    internal static SshConfig ParseSshdTOutput(string output)
    {
        var lines = output.Split('\n');
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var rawLines = new List<string>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            rawLines.Add(line);
            var spaceIndex = line.IndexOf(' ');
            if (spaceIndex <= 0)
                continue;

            var key = line.Substring(0, spaceIndex).Trim();
            var value = line.Substring(spaceIndex + 1).Trim();
            values[key] = value;
        }

        return BuildSshConfig(values, rawLines);
    }

    internal static SshConfig ParseConfigFile(string content, string sourcePath)
    {
        var lines = content.Split('\n');
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var rawLines = new List<string>();
        bool inMatchBlock = false;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            rawLines.Add(rawLine);

            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(";"))
                continue;

            // Match blocks are conditional — we skip them for global hardening checks.
            if (line.StartsWith("Match", StringComparison.OrdinalIgnoreCase))
            {
                inMatchBlock = true;
                continue;
            }

            if (inMatchBlock)
            {
                // Match-block directives are indented; global directives are not.
                // If we see a non-indented line that is not a comment, we've exited the Match block.
                if (rawLine.Length > 0 && rawLine[0] != ' ' && rawLine[0] != '\t')
                {
                    inMatchBlock = false;
                }
                else
                {
                    continue;
                }
            }

            var spaceIndex = line.IndexOf(' ');
            if (spaceIndex <= 0)
                continue;

            var key = line.Substring(0, spaceIndex).Trim();
            var value = line.Substring(spaceIndex + 1).Trim();

            // Remove inline comments
            var commentIndex = value.IndexOf('#');
            if (commentIndex >= 0)
                value = value.Substring(0, commentIndex).Trim();

            values[key] = value;
        }

        // Follow Include directives for drop-in configs.
        if (values.TryGetValue("Include", out var includePattern))
        {
            ExpandInclude(includePattern, sourcePath, values, rawLines);
        }

        return BuildSshConfig(values, rawLines);
    }

    private static void ExpandInclude(string includePattern, string sourcePath, Dictionary<string, string> values, List<string> rawLines)
    {
        try
        {
            var baseDir = Path.GetDirectoryName(sourcePath) ?? "/etc/ssh";
            var path = includePattern;
            if (!Path.IsPathRooted(path))
                path = Path.Combine(baseDir, path);

            var dir = Path.GetDirectoryName(path) ?? baseDir;
            var pattern = Path.GetFileName(path);

            if (!Directory.Exists(dir))
                return;

            foreach (var file in Directory.GetFiles(dir, pattern).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var extraContent = File.ReadAllText(file);
                    var extraLines = extraContent.Split('\n');
                    foreach (var rawLine in extraLines)
                    {
                        var line = rawLine.Trim();
                        rawLines.Add(rawLine);

                        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(";"))
                            continue;

                        var spaceIndex = line.IndexOf(' ');
                        if (spaceIndex <= 0)
                            continue;

                        var key = line.Substring(0, spaceIndex).Trim();
                        var value = line.Substring(spaceIndex + 1).Trim();

                        var commentIndex = value.IndexOf('#');
                        if (commentIndex >= 0)
                            value = value.Substring(0, commentIndex).Trim();

                        values[key] = value;
                    }
                }
                catch
                {
                    // Ignore unreadable included files.
                }
            }
        }
        catch
        {
            // Ignore expansion errors.
        }
    }

    private static SshConfig BuildSshConfig(Dictionary<string, string> values, List<string> rawLines)
    {
        return new SshConfig
        {
            ConfigReadable = true,
            PermitRootLogin = GetValue(values, "permitrootlogin"),
            PasswordAuthentication = GetValue(values, "passwordauthentication"),
            MaxAuthTries = GetIntValue(values, "maxauthtries"),
            Protocol = GetValue(values, "protocol"),
            PermitEmptyPasswords = GetValue(values, "permitemptypasswords"),
            PubkeyAuthentication = GetValue(values, "pubkeyauthentication"),
            ChallengeResponseAuthentication = GetValue(values, "challengeresponseauthentication"),
            UsePAM = GetValue(values, "usepam"),
            X11Forwarding = GetValue(values, "x11forwarding"),
            ClientAliveInterval = GetIntValue(values, "clientaliveinterval"),
            LoginGraceTime = GetSshdTimeValue(values, "logingracetime"),
            AllowUsers = GetValue(values, "allowusers"),
            AllowGroups = GetValue(values, "allowgroups"),
            DenyUsers = GetValue(values, "denyusers"),
            DenyGroups = GetValue(values, "denygroups"),
            RawLines = rawLines.ToArray()
        };
    }

    private static string? GetValue(Dictionary<string, string> values, string key)
    {
        return values.TryGetValue(key, out var value) ? value : null;
    }

    private static int? GetIntValue(Dictionary<string, string> values, string key)
    {
        if (values.TryGetValue(key, out var value) && int.TryParse(value, out var result))
            return result;
        return null;
    }

    /// <summary>
    /// Parses sshd time values which may be raw seconds or suffixed (e.g., 120, 2m, 1h).
    /// Returns seconds as an integer.
    /// </summary>
    private static int? GetSshdTimeValue(Dictionary<string, string> values, string key)
    {
        if (!values.TryGetValue(key, out var value))
            return null;

        value = value.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(value))
            return null;

        if (int.TryParse(value, out var rawSeconds))
            return rawSeconds;

        var numberPart = new string(value.TakeWhile(char.IsDigit).ToArray());
        if (!int.TryParse(numberPart, out var number))
            return null;

        var suffix = value.Substring(numberPart.Length);
        return suffix switch
        {
            "s" => number,
            "m" => number * 60,
            "h" => number * 3600,
            "d" => number * 86400,
            "w" => number * 604800,
            _ => null
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
