using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class UserAccountMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1136", TechniqueName = "Create Account", Tactic = "Persistence", WhyItMatters = "Weak account controls enable attackers to create persistent accounts." },
        new MitreTechnique { TechniqueId = "T1098", TechniqueName = "Account Manipulation", Tactic = "Persistence", WhyItMatters = "Account misconfigurations allow attackers to manipulate legitimate accounts." },
    };
}


/// <summary>
/// USER-001: UID 0 accounts beyond root.
/// </summary>
public sealed class UidZeroBeyondRootRule : IRule
{
    public string Id => "USER-001";
    public string Category => FindingCategories.UserAccount;
    public string Description => "Only root should have UID 0";
    public string WhatItChecks => "Checks /etc/passwd for any account with UID 0 other than root";
    public IReadOnlyList<string> SupportedDataSources => new[] { "passwd" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.2",
            ControlName = "Configure System Account Security",
            WhyItMatters = "UID 0 grants full superuser privileges. Additional UID-0 accounts bypass auditing and create hidden privilege-escalation paths.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var offenders = data.UserAccounts
            .Where(a => a.Uid == 0 && !a.Username.Equals("root", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (offenders.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = offenders[0];
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"{first.Username} (UID {first.Uid})",
            new Dictionary<string, string>
            {
                ["username"] = first.Username,
                ["uid"] = first.Uid.ToString(),
                ["shell"] = first.Shell
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// USER-002: Empty or unset password detection.
/// </summary>
public sealed class EmptyPasswordRule : IRule
{
    public string Id => "USER-002";
    public string Category => FindingCategories.UserAccount;
    public string Description => "No account should have an empty or unset password hash";
    public string WhatItChecks => "Checks /etc/shadow for empty password hashes or interactive accounts with no valid password set";
    public IReadOnlyList<string> SupportedDataSources => new[] { "shadow", "passwd" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.4",
            ControlName = "Configure Password Policies",
            WhyItMatters = "Empty password hashes allow authentication without any credentials. Locked hashes on interactive accounts indicate stale or unused accounts that may be re-enabled by an attacker.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.4.1 — Ensure password creation requirements are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var shadowCap = data.Capabilities.FirstOrDefault(c =>
            c.SourceName.Equals("shadow", StringComparison.OrdinalIgnoreCase));

        if (shadowCap?.Status == CapabilityStatus.PermissionLimited || shadowCap?.Status == CapabilityStatus.Unavailable)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — /etc/shadow not readable (requires root or elevated privileges).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (data.ShadowEntries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var interactiveUsers = data.UserAccounts
            .Where(a => IsInteractiveShell(a.Shell))
            .Select(a => a.Username)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in data.ShadowEntries)
        {
            var hash = entry.PasswordHash;

            // Truly empty hash → passwordless login
            if (string.IsNullOrEmpty(hash))
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{entry.Username} has empty password hash",
                    new Dictionary<string, string>
                    {
                        ["username"] = entry.Username,
                        ["reason"] = "empty hash"
                    }, CisMappings, MitreTechniques);
            }

            // Locked / no-password-set markers on interactive accounts
            if (interactiveUsers.Contains(entry.Username) && IsLockedHash(hash))
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity.High,
                    $"{entry.Username} has no valid password set ({hash})",
                    new Dictionary<string, string>
                    {
                        ["username"] = entry.Username,
                        ["reason"] = "no valid password set"
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsLockedHash(string hash)
    {
        return hash is "!" or "!!" or "*";
    }

    private static bool IsInteractiveShell(string shell)
    {
        return !shell.Equals("/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/sbin/nologin", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/sbin/nologin", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// USER-003: Password aging policy from /etc/login.defs and per-user shadow entries.
/// </summary>
public sealed class PasswordAgingRule : IRule
{
    public string Id => "USER-003";
    public string Category => FindingCategories.UserAccount;
    public string Description => "Password aging should enforce regular rotation and minimum lifetime";
    public string WhatItChecks => "Checks PASS_MAX_DAYS, PASS_MIN_DAYS, and PASS_WARN_AGE in /etc/login.defs and per-user shadow max days";
    public IReadOnlyList<string> SupportedDataSources => new[] { "login.defs", "shadow", "passwd" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.4",
            ControlName = "Configure Password Policies",
            WhyItMatters = "Without password aging, credentials may remain unchanged for years, increasing exposure from leaks and brute-force attempts.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.4.1 — Ensure password creation requirements are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoginDefs is { Readable: true } defs)
        {
            var violations = new List<string>();
            var vars = new Dictionary<string, string>();

            if (defs.PassMaxDays is null or > 90)
            {
                violations.Add($"PASS_MAX_DAYS = {defs.PassMaxDays?.ToString() ?? "unset"} (expected <= 90)");
                vars["maxDays"] = defs.PassMaxDays?.ToString() ?? "unset";
            }

            if (defs.PassMinDays is null or < 1)
            {
                violations.Add($"PASS_MIN_DAYS = {defs.PassMinDays?.ToString() ?? "unset"} (expected >= 1)");
                vars["minDays"] = defs.PassMinDays?.ToString() ?? "unset";
            }

            if (defs.PassWarnAge is null or < 7)
            {
                violations.Add($"PASS_WARN_AGE = {defs.PassWarnAge?.ToString() ?? "unset"} (expected >= 7)");
                vars["warnAge"] = defs.PassWarnAge?.ToString() ?? "unset";
            }

            if (violations.Count > 0)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    string.Join("; ", violations),
                    vars, CisMappings, MitreTechniques);
            }
        }

        var interactiveUsers = data.UserAccounts
            .Where(a => a.Uid >= 1000 && IsInteractiveShell(a.Shell))
            .Select(a => a.Username)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in data.ShadowEntries)
        {
            if (!interactiveUsers.Contains(entry.Username))
                continue;

            if (entry.MaxDays is null or > 90 or 0)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{entry.Username} max days = {entry.MaxDays?.ToString() ?? "unset"}",
                    new Dictionary<string, string>
                    {
                        ["username"] = entry.Username,
                        ["maxDays"] = entry.MaxDays?.ToString() ?? "unset",
                        ["expected"] = "<= 90"
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsInteractiveShell(string shell)
    {
        return !shell.Equals("/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/sbin/nologin", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/sbin/nologin", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// USER-004: PAM password complexity requirements.
/// </summary>
public sealed class PamPasswordComplexityRule : IRule
{
    public string Id => "USER-004";
    public string Category => FindingCategories.UserAccount;
    public string Description => "PAM should enforce password complexity";
    public string WhatItChecks => "Checks PAM password-stack configuration for pwquality, cracklib, or passwdqc modules";
    public IReadOnlyList<string> SupportedDataSources => new[] { "pam" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.4",
            ControlName = "Configure Password Policies",
            WhyItMatters = "Without complexity requirements users choose weak passwords that are trivial to brute-force or guess.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.4.1 — Ensure password creation requirements are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.PamConfig is not { Readable: true, RawLines.Count: > 0 })
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var hasComplexity = data.PamConfig.RawLines.Any(line =>
        {
            var l = line.Trim().ToLowerInvariant();
            // Only match lines in the password management stack
            if (!l.StartsWith("password"))
                return false;
            return l.Contains("pam_pwquality.so") || l.Contains("pam_cracklib.so") || l.Contains("pam_passwdqc.so");
        });

        // Also accept pwquality.conf settings as evidence of complexity configuration
        var hasPwqualityConf = data.PamConfig.RawLines.Any(line =>
        {
            var l = line.Trim().ToLowerInvariant();
            return l.StartsWith("minlen") || l.StartsWith("minclass") || l.StartsWith("dcredit")
                   || l.StartsWith("ucredit") || l.StartsWith("lcredit") || l.StartsWith("ocredit");
        });

        if (hasComplexity || hasPwqualityConf)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            "No PAM password complexity module found",
            new Dictionary<string, string>
            {
                ["expectedModules"] = "pam_pwquality.so, pam_cracklib.so, or pam_passwdqc.so"
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// USER-005: Inactive or locked interactive accounts.
/// </summary>
public sealed class InactiveAccountsRule : IRule
{
    public string Id => "USER-005";
    public string Category => FindingCategories.UserAccount;
    public string Description => "Inactive or locked interactive accounts should be reviewed";
    public string WhatItChecks => "Checks for interactive accounts that are locked, have no password, or have an expired account expiry date";
    public IReadOnlyList<string> SupportedDataSources => new[] { "shadow", "passwd" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.2",
            ControlName = "Configure System Account Security",
            WhyItMatters = "Stale interactive accounts provide additional attack surface and may be re-enabled or exploited by attackers.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.5 — Ensure inactive accounts are locked or removed"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.ShadowEntries.Count == 0 || data.UserAccounts.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var todayDays = (int)(DateTime.UtcNow.Date - new DateTime(1970, 1, 1)).TotalDays;

        var shadowByUser = data.ShadowEntries
            .ToLookup(s => s.Username, StringComparer.OrdinalIgnoreCase);

        foreach (var account in data.UserAccounts)
        {
            if (!IsInteractiveShell(account.Shell))
                continue;

            if (account.Uid < 1000)
                continue; // Focus on regular user accounts

            var shadows = shadowByUser[account.Username];
            if (!shadows.Any())
                continue;

            var shadow = shadows.First();

            if (IsLockedHash(shadow.PasswordHash))
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} is locked / has no password",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["reason"] = "locked or no password set"
                    }, CisMappings, MitreTechniques);
            }

            if (shadow.ExpireDate.HasValue && shadow.ExpireDate.Value < todayDays)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} account expired",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["reason"] = "account expiry date has passed"
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsLockedHash(string hash)
    {
        return hash is "!" or "!!" or "*";
    }

    private static bool IsInteractiveShell(string shell)
    {
        return !shell.Equals("/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/sbin/nologin", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/sbin/nologin", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// USER-006: Duplicate UIDs.
/// </summary>
public sealed class DuplicateUidsRule : IRule
{
    public string Id => "USER-006";
    public string Category => FindingCategories.UserAccount;
    public string Description => "Each UID should be unique";
    public string WhatItChecks => "Checks /etc/passwd for multiple usernames sharing the same UID";
    public IReadOnlyList<string> SupportedDataSources => new[] { "passwd" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.2",
            ControlName = "Configure System Account Security",
            WhyItMatters = "Duplicate UIDs break audit trails and access-control assumptions. One user's files become indistinguishable from another's at the kernel level.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.UserAccounts.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var groups = data.UserAccounts.GroupBy(a => a.Uid).Where(g => g.Count() > 1).ToList();
        if (groups.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = groups[0];
        var names = string.Join(", ", first.Select(a => a.Username));

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"UID {first.Key}: {names}",
            new Dictionary<string, string>
            {
                ["uid"] = first.Key.ToString(),
                ["usernames"] = names
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// USER-007: Accounts without home directories.
/// </summary>
public sealed class MissingHomeDirectoryRule : IRule
{
    public string Id => "USER-007";
    public string Category => FindingCategories.UserAccount;
    public string Description => "Regular user accounts should have a home directory";
    public string WhatItChecks => "Checks /etc/passwd for interactive users (UID >= 1000) whose home directory is missing";
    public IReadOnlyList<string> SupportedDataSources => new[] { "passwd" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.2",
            ControlName = "Configure System Account Security",
            WhyItMatters = "Missing home directories indicate improperly provisioned or cleaned-up accounts. They can also break applications that expect user-specific configuration files.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.6 — Ensure all users' home directories exist"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        foreach (var account in data.UserAccounts)
        {
            if (account.Uid < 1000)
                continue;

            if (!IsInteractiveShell(account.Shell))
                continue;

            if (string.IsNullOrEmpty(account.HomeDirectory))
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} has no home directory set",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["homeDirectory"] = "(unset)"
                    }, CisMappings, MitreTechniques);
            }

            if (!account.HomeDirectoryExists)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} home directory missing: {account.HomeDirectory}",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["homeDirectory"] = account.HomeDirectory
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsInteractiveShell(string shell)
    {
        return !shell.Equals("/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/sbin/nologin", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/sbin/nologin", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// USER-008: PAM faillock should be configured for account lockout and failed-login tracking.
/// </summary>
public sealed class PamFaillockConfiguredRule : IRule
{
    public string Id => "USER-008";
    public string Category => FindingCategories.UserAccount;
    public string Description => "PAM faillock should be configured for failed-login tracking and account lockout";
    public string WhatItChecks => "Checks the auth PAM stack for pam_faillock.so with preauth and authfail, and verifies faillock.conf is present";
    public IReadOnlyList<string> SupportedDataSources => new[] { "pam" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.3",
            ControlName = "Configure PAM",
            WhyItMatters = "Without faillock, attackers can perform unlimited authentication attempts. Account lockout after a small number of failures is required by NIST 800-53 AC-7 and CIS benchmarks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.3.2 — Ensure lockout for failed password attempts is configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.PamConfig is not { Readable: true } ||
            (data.PamConfig.RawLines.Count == 0 && data.PamConfig.RawLinesByFile.Count == 0))
            return RuleResult.NotApplicable(Id, Category, Id, Description, CisMappings, MitreTechniques);

        // Use per-file data when available; fall back to flat RawLines for compatibility.
        var filesToCheck = data.PamConfig.RawLinesByFile.Count > 0
            ? data.PamConfig.RawLinesByFile
            : new Dictionary<string, string[]> { ["merged"] = data.PamConfig.RawLines.ToArray() };

        var authFilesWithLines = filesToCheck
            .Where(kv => kv.Value.Any(l => l.TrimStart().StartsWith("auth", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (authFilesWithLines.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var filesMissingFaillock = new List<string>();
        foreach (var (filePath, lines) in authFilesWithLines)
        {
            var authLines = lines
                .Where(l => l.TrimStart().StartsWith("auth", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim().ToLowerInvariant())
                .ToList();

            var hasPreauth = authLines.Any(l => l.Contains("pam_faillock.so") && l.Contains("preauth"));
            var hasAuthfail = authLines.Any(l => l.Contains("pam_faillock.so") && l.Contains("authfail"));

            if (!hasPreauth || !hasAuthfail)
            {
                filesMissingFaillock.Add(filePath);
            }
        }

        // Check faillock.conf specifically, not any file
        var hasFaillockConf = data.PamConfig.RawLinesByFile.TryGetValue("/etc/security/faillock.conf", out var faillockLines)
            ? faillockLines.Any(l =>
            {
                var trimmed = l.Trim().ToLowerInvariant();
                return !trimmed.StartsWith('#') &&
                       (trimmed.StartsWith("deny") || trimmed.StartsWith("unlock_time") || trimmed.StartsWith("fail_interval"));
            })
            : data.PamConfig.RawLines.Any(l =>
            {
                var trimmed = l.Trim().ToLowerInvariant();
                // Fallback: require '=' to match key=value lines typical of faillock.conf,
                // avoiding false positives on PAM module arguments.
                return !trimmed.StartsWith('#') && trimmed.Contains('=') &&
                       (trimmed.StartsWith("deny") || trimmed.StartsWith("unlock_time") || trimmed.StartsWith("fail_interval"));
            });

        if (filesMissingFaillock.Count == 0 && hasFaillockConf)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var missing = new List<string>();
        if (filesMissingFaillock.Count > 0)
            missing.Add($"faillock preauth/authfail in {string.Join(", ", filesMissingFaillock)}");
        if (!hasFaillockConf)
            missing.Add("faillock.conf settings");

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"Missing: {string.Join("; ", missing)}",
            new Dictionary<string, string>
            {
                ["missing"] = string.Join("; ", missing),
                ["expected"] = "pam_faillock.so preauth and authfail in every auth stack, with faillock.conf"
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// USER-009: PAM password quality should enforce detailed complexity (minlen, minclass, credits).
/// </summary>
public sealed class PamPasswordQualityDetailedRule : IRule
{
    public string Id => "USER-009";
    public string Category => FindingCategories.UserAccount;
    public string Description => "PAM password quality should enforce minimum length, character classes, and credit requirements";
    public string WhatItChecks => "Checks pwquality.conf or PAM arguments for minlen >= 14, minclass >= 3, and at least one credit setting";
    public IReadOnlyList<string> SupportedDataSources => new[] { "pam" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.4",
            ControlName = "Configure Password Policies",
            WhyItMatters = "Weak passwords are the primary vector for brute-force and credential-guessing attacks. Enforcing length, diversity, and credit requirements raises the cost of attack exponentially.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.4.1 — Ensure password creation requirements are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.PamConfig is not { Readable: true } ||
            (data.PamConfig.RawLines.Count == 0 && data.PamConfig.RawLinesByFile.Count == 0))
            return RuleResult.NotApplicable(Id, Category, Id, Description, CisMappings, MitreTechniques);

        int? minlen = null;
        int? minclass = null;
        var hasCredit = false;

        var linesToCheck = data.PamConfig.RawLinesByFile.Count > 0
            ? data.PamConfig.RawLinesByFile.Values.SelectMany(v => v)
            : data.PamConfig.RawLines;

        // Note: last-value-wins semantics. The scanner orders pwquality.conf after PAM stack files,
        // so settings in pwquality.conf take precedence over inline module arguments.
        foreach (var raw in linesToCheck)
        {
            var line = raw.Trim().ToLowerInvariant();
            if (line.StartsWith('#'))
                continue;

            // pwquality.conf style: key = value
            if (line.StartsWith("minlen"))
            {
                var parts = line.Split(new[] { '=', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && int.TryParse(parts[1], out var v))
                    minlen = v;
            }
            else if (line.StartsWith("minclass"))
            {
                var parts = line.Split(new[] { '=', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && int.TryParse(parts[1], out var v))
                    minclass = v;
            }
            else if (line.StartsWith("dcredit") || line.StartsWith("ucredit") || line.StartsWith("lcredit") || line.StartsWith("ocredit"))
            {
                hasCredit = true;
            }
            // PAM module argument style
            else if (line.Contains("pam_pwquality.so") || line.Contains("pam_cracklib.so"))
            {
                var args = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var arg in args)
                {
                    if (arg.StartsWith("minlen="))
                    {
                        if (int.TryParse(arg.Split('=')[1], out var v))
                            minlen = v;
                    }
                    else if (arg.StartsWith("minclass="))
                    {
                        if (int.TryParse(arg.Split('=')[1], out var v))
                            minclass = v;
                    }
                    else if (arg.StartsWith("dcredit=") || arg.StartsWith("ucredit=") || arg.StartsWith("lcredit=") || arg.StartsWith("ocredit="))
                    {
                        hasCredit = true;
                    }
                }
            }
        }

        var violations = new List<string>();
        var vars = new Dictionary<string, string>();

        if (minlen is null or < 14)
        {
            violations.Add($"minlen = {minlen?.ToString() ?? "unset"} (expected >= 14)");
            vars["minlen"] = minlen?.ToString() ?? "unset";
        }

        if (minclass is null or < 3)
        {
            violations.Add($"minclass = {minclass?.ToString() ?? "unset"} (expected >= 3)");
            vars["minclass"] = minclass?.ToString() ?? "unset";
        }

        if (!hasCredit)
        {
            violations.Add("No credit settings (dcredit, ucredit, lcredit, ocredit) found");
            vars["credits"] = "none";
        }

        if (violations.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        vars["violations"] = string.Join("; ", violations);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            string.Join("; ", violations),
            vars, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// USER-010: PAM auth stack should have a required/requisite module before any sufficient module.
/// </summary>
public sealed class PamAuthRequiredRule : IRule
{
    public string Id => "USER-010";
    public string Category => FindingCategories.UserAccount;
    public string Description => "PAM auth stack should require at least one required or requisite module before sufficient modules";
    public string WhatItChecks => "Checks that the auth PAM stack ordering prevents bypass by placing required/requisite before sufficient";
    public IReadOnlyList<string> SupportedDataSources => new[] { "pam" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.3",
            ControlName = "Configure PAM",
            WhyItMatters = "A sufficient module placed before required/requisite can short-circuit authentication, allowing bypass if the sufficient module succeeds. Proper ordering ensures every authentication path satisfies mandatory checks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.3.1 — Ensure password hashing algorithm is configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => UserAccountMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.PamConfig is not { Readable: true } ||
            (data.PamConfig.RawLines.Count == 0 && data.PamConfig.RawLinesByFile.Count == 0))
            return RuleResult.NotApplicable(Id, Category, Id, Description, CisMappings, MitreTechniques);

        // Check each file independently; fail if ANY file has sufficient before required.
        var filesToCheck = data.PamConfig.RawLinesByFile.Count > 0
            ? data.PamConfig.RawLinesByFile
            : new Dictionary<string, string[]> { ["merged"] = data.PamConfig.RawLines.ToArray() };

        foreach (var (filePath, lines) in filesToCheck)
        {
            var authLines = lines
                .Where(l => l.TrimStart().StartsWith("auth", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim().ToLowerInvariant())
                .ToList();

            if (authLines.Count == 0)
                continue;

            bool foundRequired = false;
            bool sufficientBeforeRequired = false;

            foreach (var line in authLines)
            {
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3)
                    continue;

                var control = parts[1];
                if (IsMandatoryControl(control))
                {
                    foundRequired = true;
                }
                else if (control is "sufficient" && !foundRequired)
                {
                    sufficientBeforeRequired = true;
                    break;
                }
            }

            if (sufficientBeforeRequired)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"Auth stack in {filePath} has sufficient module before required/requisite",
                    new Dictionary<string, string>
                    {
                        ["file"] = filePath,
                        ["issue"] = "sufficient placed before required/requisite in auth stack",
                        ["expected"] = "required or requisite module must appear before any sufficient module"
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsMandatoryControl(string control)
    {
        if (control is "required" or "requisite" or "binding")
            return true;

        if (control.StartsWith("[", StringComparison.Ordinal))
        {
            // Bracketed controls are usually mandatory, but common permissive patterns
            // like default=ignore or default=ok effectively make them optional.
            var lower = control.ToLowerInvariant();
            if (lower.Contains("default=ignore") || lower.Contains("default=ok"))
                return false;
            return true;
        }

        return false;
    }
}
