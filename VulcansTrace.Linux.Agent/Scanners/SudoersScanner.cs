namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans sudoers configuration from /etc/sudoers and /etc/sudoers.d.
/// </summary>
public sealed class SudoersScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Sudoers";

    private static readonly string MainSudoersPath = "/etc/sudoers";
    private static readonly string SudoersDPath = "/etc/sudoers.d";

    /// <summary>
    /// Recognized sudoers command tags (the tokens that may precede a command list as
    /// <c>TAG:</c>). Used to peel the leading tag prefix off a privilege line.
    /// </summary>
    private static readonly HashSet<string> SudoersTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "NOPASSWD", "PASSWD",
        "NOEXEC", "EXEC",
        "SETENV", "NOSETENV",
        "LOG_INPUT", "NOLOG_INPUT",
        "LOG_OUTPUT", "NOLOG_OUTPUT",
        "FOLLOW", "NOFOLLOW",
        "MAIL", "NOMAIL",
        "TIMEOUT", "NOTIMEOUT"
    };

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        if (!File.Exists(MainSudoersPath))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "sudoers",
                Status = CapabilityStatus.Unavailable,
                Detail = $"{MainSudoersPath} not found",
                Command = MainSudoersPath
            });
            builder.SetSudoersConfig(new SudoersConfig { ConfigReadable = false });
            return;
        }

        var (mainMode, mainOwner, mainGroup, statOk, statError) = await GetFilePermissionsAsync(MainSudoersPath, cancellationToken);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "sudoers",
            Status = statOk ? CapabilityStatus.Available : CapabilityStatus.PermissionLimited,
            Detail = statError,
            Command = "stat -c '%a %U %G %n' /etc/sudoers"
        });

        var allLines = new List<(string FilePath, string Line)>();
        var entries = new List<SudoersEntry>();
        bool hasPasswordlessFullSudo = false;
        bool hasFullSudo = false;
        bool hasNoAuthenticate = false;
        bool hasSecurePath = false;

        try
        {
            await CollectLinesAsync(MainSudoersPath, allLines, cancellationToken);

            if (Directory.Exists(SudoersDPath))
            {
                foreach (var file in Directory.GetFiles(SudoersDPath).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    await CollectLinesAsync(file, allLines, cancellationToken);
                }
            }

            foreach (var (filePath, rawLine) in allLines)
            {
                var line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;

                if (line.StartsWith("Defaults", StringComparison.OrdinalIgnoreCase))
                {
                    // Only !authenticate globally disables sudo password prompts.
                    // (!rootpw is the *safe* default — it means "use the invoking user's
                    // password"; the risky form is `rootpw` without the negation.)
                    if (line.Contains("!authenticate", StringComparison.OrdinalIgnoreCase))
                    {
                        hasNoAuthenticate = true;
                    }

                    if (line.Contains("secure_path", StringComparison.OrdinalIgnoreCase))
                    {
                        hasSecurePath = true;
                    }

                    continue;
                }

                if (line.Equals("includedir", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("includedir ", StringComparison.OrdinalIgnoreCase) ||
                    line.Equals("include", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("include ", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var entry = ParsePrivilegeLine(filePath, rawLine);
                if (entry == null)
                    continue;

                entries.Add(entry);

                bool isFullSudo = IsFullSudoEntry(entry);
                bool isNoPasswd = entry.NoPasswd;

                if (isFullSudo)
                {
                    hasFullSudo = true;
                    if (isNoPasswd)
                    {
                        hasPasswordlessFullSudo = true;
                    }
                }
            }

            builder.SetSudoersConfig(new SudoersConfig
            {
                ConfigReadable = true,
                MainFileMode = mainMode,
                MainFileOwner = mainOwner,
                MainFileGroup = mainGroup,
                HasPasswordlessFullSudo = hasPasswordlessFullSudo,
                HasFullSudo = hasFullSudo,
                HasNoAuthenticate = hasNoAuthenticate,
                HasSecurePath = hasSecurePath,
                Entries = entries,
                RawLines = allLines.Select(l => l.Line).ToArray()
            });
        }
        catch (Exception ex)
        {
            builder.AddWarning($"Sudoers scan skipped: {ex.Message}");
            builder.SetSudoersConfig(new SudoersConfig
            {
                ConfigReadable = false,
                MainFileMode = mainMode,
                MainFileOwner = mainOwner,
                MainFileGroup = mainGroup
            });
        }
    }

    private static async Task<(string? Mode, string? Owner, string? Group, bool Ok, string? Error)> GetFilePermissionsAsync(
        string path, CancellationToken ct)
    {
        var (stdout, stderr, success) = await RunCommandAsync("stat", new[] { "-c", "%a %U %G %n", path }, ct);
        if (!success || string.IsNullOrWhiteSpace(stdout))
            return (null, null, null, false, stderr);

        var entry = FilePermissionScanner.ParseStatLine(stdout.Split('\n')[0].Trim());
        if (entry == null)
            return (null, null, null, false, stderr);

        return (entry.Mode, entry.Owner, entry.Group, true, stderr);
    }

    private static async Task CollectLinesAsync(string path, List<(string FilePath, string Line)> target, CancellationToken ct)
    {
        string content;
        try
        {
            content = await File.ReadAllTextAsync(path, ct);
        }
        catch
        {
            return;
        }

        var lines = content.Split('\n');
        foreach (var line in lines)
        {
            target.Add((path, line));
        }
    }

    internal static SudoersEntry? ParsePrivilegeLine(string sourceFile, string rawLine)
    {
        var line = rawLine.Trim();
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            return null;

        // Defaults lines are not privilege lines.
        if (line.StartsWith("Defaults", StringComparison.OrdinalIgnoreCase))
            return null;

        // Skip include directives.
        if (line.StartsWith("include ", StringComparison.OrdinalIgnoreCase) ||
            line.StartsWith("includedir ", StringComparison.OrdinalIgnoreCase) ||
            line.Equals("include", StringComparison.OrdinalIgnoreCase) ||
            line.Equals("includedir", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Remove inline comments.
        var commentIndex = line.IndexOf('#');
        if (commentIndex >= 0)
            line = line.Substring(0, commentIndex).Trim();

        if (string.IsNullOrWhiteSpace(line))
            return null;

        // Sudoers privilege lines have the form:
        //   user host = (runas) NOPASSWD: commands
        // or
        //   %group host = commands
        // The '=' separator is required.
        var equalsIndex = line.IndexOf('=');
        if (equalsIndex < 0)
            return null;

        var left = line.Substring(0, equalsIndex).Trim();
        var right = line.Substring(equalsIndex + 1).Trim();

        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
            return null;

        // Split left side into principal and host list.
        var leftParts = left.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (leftParts.Length == 0)
            return null;

        var principal = leftParts[0];
        var hosts = leftParts.Length > 1 ? string.Join(" ", leftParts.Skip(1)) : "ALL";

        bool isGroup = principal.StartsWith('%');

        // Parse right side for RunAs specification and tags.
        var runAs = "";
        var commands = right;
        bool noPasswd = false;

        if (commands.StartsWith('('))
        {
            var closeIndex = commands.IndexOf(')');
            if (closeIndex > 0)
            {
                runAs = commands.Substring(0, closeIndex + 1);
                commands = commands.Substring(closeIndex + 1).Trim();
            }
        }

        // Sudoers allows zero or more tags before the command list, each followed by ':'
        // (e.g. "NOEXEC: NOPASSWD: /bin/foo"). Consume the entire tag prefix so NOPASSWD is
        // detected wherever it appears in the sequence, and 'commands' holds the real spec.
        while (commands.Length > 0)
        {
            var colon = commands.IndexOf(':');
            if (colon <= 0)
                break;

            var token = commands.Substring(0, colon).Trim();
            if (token.Length == 0)
                break;

            // Tags like TIMEOUT=30 carry an argument; the tag name is the part before '='.
            var name = token.Split('=')[0];
            if (!SudoersTags.Contains(name))
                break; // Not a recognized tag — the remainder is the command spec.

            if (name.Equals("NOPASSWD", StringComparison.OrdinalIgnoreCase))
                noPasswd = true;

            commands = commands.Substring(colon + 1).Trim();
        }

        return new SudoersEntry
        {
            SourceFile = sourceFile,
            Principal = principal,
            IsGroup = isGroup,
            Hosts = hosts,
            RunAs = runAs,
            Commands = commands,
            NoPasswd = noPasswd,
            RawLine = rawLine.Trim()
        };
    }

    internal static bool IsFullSudoEntry(SudoersEntry entry)
    {
        if (!SudoersListContainsAtom(entry.Commands, "ALL", ' ', '\t', ','))
            return false;

        var hostsAll = SudoersListContainsAtom(entry.Hosts, "ALL", ' ', '\t', ',');
        var runAsAll = string.IsNullOrWhiteSpace(entry.RunAs) ||
                       SudoersListContainsAtom(entry.RunAs.Trim('(', ')'), "ALL", ' ', '\t', ',', ':');
        return hostsAll && runAsAll;
    }

    private static bool SudoersListContainsAtom(string value, string atom, params char[] separators)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return value
            .Split(separators, StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .Any(part => part.Equals(atom, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
