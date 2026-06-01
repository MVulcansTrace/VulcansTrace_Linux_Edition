namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans local user accounts, shadow entries, password aging policies, and PAM configuration.
/// Note: This scanner only reads local /etc/passwd and /etc/shadow. LDAP, NIS, or Active Directory
/// users are not covered and will not be reflected in the scan results.
/// </summary>
public sealed class UserAccountScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "UserAccount";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        await ScanPasswdAsync(builder, cancellationToken);
        await ScanShadowAsync(builder, cancellationToken);
        await ScanLoginDefsAsync(builder, cancellationToken);
        await ScanPamAsync(builder, cancellationToken);
    }

    private static async Task ScanPasswdAsync(ScanDataBuilder builder, CancellationToken ct)
    {
        const string path = "/etc/passwd";
        if (!File.Exists(path))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "passwd",
                Status = CapabilityStatus.Unavailable,
                Detail = "/etc/passwd not found."
            });
            return;
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(path, ct);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;
                var account = ParsePasswdLine(line);
                if (account != null)
                    builder.AddUserAccount(account);
            }

            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "passwd",
                Status = CapabilityStatus.Available
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "passwd",
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    internal static UserAccount? ParsePasswdLine(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 7)
            return null;
        if (!int.TryParse(parts[2], out var uid))
            return null;
        if (!int.TryParse(parts[3], out var gid))
            return null;

        var homeDir = parts[5];
        return new UserAccount
        {
            Username = parts[0],
            Uid = uid,
            Gid = gid,
            Gecos = parts[4],
            HomeDirectory = homeDir,
            Shell = parts[6],
            HomeDirectoryExists = !string.IsNullOrEmpty(homeDir) && Directory.Exists(homeDir)
        };
    }

    private static async Task ScanShadowAsync(ScanDataBuilder builder, CancellationToken ct)
    {
        const string path = "/etc/shadow";
        if (!File.Exists(path))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "shadow",
                Status = CapabilityStatus.Unavailable,
                Detail = "/etc/shadow not found."
            });
            return;
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(path, ct);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;
                var entry = ParseShadowLine(line);
                if (entry != null)
                    builder.AddShadowEntry(entry);
            }

            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "shadow",
                Status = CapabilityStatus.Available
            });
        }
        catch (UnauthorizedAccessException)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "shadow",
                Status = CapabilityStatus.PermissionLimited,
                Detail = "Permission denied reading /etc/shadow."
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "shadow",
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    internal static ShadowEntry? ParseShadowLine(string line)
    {
        var parts = line.Split(':');
        if (parts.Length < 8)
            return null;

        return new ShadowEntry
        {
            Username = parts[0],
            PasswordHash = parts[1],
            LastChange = ParseOptionalInt(parts[2]),
            MinDays = ParseOptionalInt(parts[3]),
            MaxDays = ParseOptionalInt(parts[4]),
            WarnDays = ParseOptionalInt(parts[5]),
            InactiveDays = ParseOptionalInt(parts[6]),
            ExpireDate = ParseOptionalInt(parts[7])
        };
    }

    private static int? ParseOptionalInt(string value)
    {
        return int.TryParse(value, out var result) ? result : null;
    }

    private static async Task ScanLoginDefsAsync(ScanDataBuilder builder, CancellationToken ct)
    {
        const string path = "/etc/login.defs";
        if (!File.Exists(path))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "login.defs",
                Status = CapabilityStatus.Unavailable,
                Detail = "/etc/login.defs not found."
            });
            return;
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(path, ct);
            var defs = ParseLoginDefs(lines);
            builder.SetLoginDefs(defs);
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "login.defs",
                Status = CapabilityStatus.Available
            });
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "login.defs",
                Status = CapabilityStatus.Unavailable,
                Detail = ex.Message
            });
        }
    }

    internal static LoginDefs ParseLoginDefs(string[] lines)
    {
        int? passMaxDays = null;
        int? passMinDays = null;
        int? passMinLen = null;
        int? passWarnAge = null;
        string? encryptMethod = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                continue;

            var parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                continue;

            var key = parts[0].ToUpperInvariant();
            var value = parts[1].Trim();

            switch (key)
            {
                case "PASS_MAX_DAYS" when int.TryParse(value, out var v):
                    passMaxDays = v;
                    break;
                case "PASS_MIN_DAYS" when int.TryParse(value, out var v):
                    passMinDays = v;
                    break;
                case "PASS_MIN_LEN" when int.TryParse(value, out var v):
                    passMinLen = v;
                    break;
                case "PASS_WARN_AGE" when int.TryParse(value, out var v):
                    passWarnAge = v;
                    break;
                case "ENCRYPT_METHOD":
                    encryptMethod = value;
                    break;
            }
        }

        return new LoginDefs
        {
            Readable = true,
            PassMaxDays = passMaxDays,
            PassMinDays = passMinDays,
            PassMinLen = passMinLen,
            PassWarnAge = passWarnAge,
            EncryptMethod = encryptMethod
        };
    }

    private static async Task ScanPamAsync(ScanDataBuilder builder, CancellationToken ct)
    {
        var pamPaths = new[]
        {
            "/etc/pam.d/common-password",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/pam.d/sshd",
            "/etc/security/pwquality.conf",
            "/etc/security/faillock.conf"
        };

        var allLines = new List<string>();
        var linesByFile = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var anyFound = false;

        foreach (var path in pamPaths)
        {
            if (!File.Exists(path))
                continue;

            anyFound = true;
            try
            {
                var lines = await File.ReadAllLinesAsync(path, ct);
                allLines.AddRange(lines);
                linesByFile[path] = lines;
            }
            catch (UnauthorizedAccessException)
            {
                // Keep going — partial data is still useful
            }
            catch (Exception ex)
            {
                builder.AddWarning($"PAM scan error for {path}: {ex.Message}");
            }
        }

        if (!anyFound)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "pam",
                Status = CapabilityStatus.Unavailable,
                Detail = "No PAM configuration files found."
            });
            return;
        }

        if (allLines.Count == 0)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "pam",
                Status = CapabilityStatus.PermissionLimited,
                Detail = "PAM files exist but could not be read (permission denied or read errors)."
            });
            return;
        }

        builder.SetPamConfig(new PamConfig
        {
            Readable = true,
            RawLines = allLines.ToArray(),
            RawLinesByFile = linesByFile
        });

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "pam",
            Status = CapabilityStatus.Available
        });
    }
}
