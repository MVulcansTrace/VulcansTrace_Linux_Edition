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
        // Prefer sshd -T when available because it resolves includes, defaults, and recursion.
        var (testOutput, testError, testOk) = await RunCommandAsync("sshd", new[] { "-T" }, cancellationToken);
        var testStatus = DataSourceCapability.FromCommandResult(testOk, testOutput, testError);
        builder.AddCapability(new DataSourceCapability { SourceName = "sshd -T", Status = testStatus, Detail = testError });

        if (testOk && !string.IsNullOrWhiteSpace(testOutput))
        {
            var config = ParseSshdTOutput(testOutput);
            builder.SetSshConfig(config);
            return;
        }

        // Fallback: read config files directly with async recursive include expansion.
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
            builder.SetSshConfig(new SshConfig { ConfigReadable = false });
            return;
        }

        try
        {
            var lines = await ReadConfigWithIncludesAsync(configPath, cancellationToken);
            var config = ParseConfigLines(lines);
            builder.SetSshConfig(config);
            builder.AddCapability(new DataSourceCapability { SourceName = "sshd_config", Status = CapabilityStatus.Available });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability { SourceName = "sshd_config", Status = CapabilityStatus.Unavailable, Detail = ex.Message });
            builder.AddWarning($"SSH config scan skipped: failed to read {configPath}. {ex.Message}");
            builder.SetSshConfig(new SshConfig { ConfigReadable = false });
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

    /// <summary>
    /// Parses an already-resolved sequence of sshd_config lines (includes processed inline).
    /// Match blocks are skipped for global hardening checks.
    /// </summary>
    internal static SshConfig ParseConfigLines(IEnumerable<string> lines)
    {
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

        return BuildSshConfig(values, rawLines);
    }

    /// <summary>
    /// Legacy entry point for tests that don't need include resolution.
    /// </summary>
    internal static SshConfig ParseConfigFile(string content, string sourcePath)
    {
        var lines = content.Split('\n');
        return ParseConfigLines(lines);
    }

    /// <summary>
    /// Reads a config file and recursively expands Include directives inline using async I/O.
    /// Guards against circular includes.
    /// </summary>
    private static async Task<List<string>> ReadConfigWithIncludesAsync(string path, CancellationToken ct, HashSet<string>? visited = null)
    {
        visited ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!visited.Add(path))
            return new List<string>(); // Circular include guard

        var lines = new List<string>();
        string content;
        try
        {
            content = await File.ReadAllTextAsync(path, ct);
        }
        catch
        {
            return lines; // Unreadable file — skip silently
        }

        var fileLines = content.Split('\n');
        var baseDir = Path.GetDirectoryName(path) ?? "/etc/ssh";

        foreach (var rawLine in fileLines)
        {
            lines.Add(rawLine);

            var line = rawLine.Trim();
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

            if (!key.Equals("Include", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var resolved in ResolveIncludePattern(value, baseDir))
            {
                var includedLines = await ReadConfigWithIncludesAsync(resolved, ct, visited);
                lines.AddRange(includedLines);
            }
        }

        return lines;
    }

    private static IEnumerable<string> ResolveIncludePattern(string includePattern, string baseDir)
    {
        try
        {
            var path = includePattern;
            if (!Path.IsPathRooted(path))
                path = Path.Combine(baseDir, path);

            var dir = Path.GetDirectoryName(path) ?? baseDir;
            var pattern = Path.GetFileName(path);

            if (!Directory.Exists(dir))
                return Array.Empty<string>();

            return Directory.GetFiles(dir, pattern).OrderBy(f => f, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return Array.Empty<string>();
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
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
