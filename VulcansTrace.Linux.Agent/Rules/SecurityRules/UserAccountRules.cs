using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

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

    public RuleResult Evaluate(ScanData data)
    {
        var offenders = data.UserAccounts
            .Where(a => a.Uid == 0 && !a.Username.Equals("root", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (offenders.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

        var first = offenders[0];
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"{first.Username} (UID {first.Uid})",
            new Dictionary<string, string>
            {
                ["username"] = first.Username,
                ["uid"] = first.Uid.ToString(),
                ["shell"] = first.Shell
            }, CisMappings);
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
                CisMappings = CisMappings
            };
        }

        if (data.ShadowEntries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

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
                    }, CisMappings);
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
                    }, CisMappings);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings);
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
                    vars, CisMappings);
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
                    }, CisMappings);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.PamConfig is not { Readable: true, RawLines.Count: > 0 })
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

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
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            "No PAM password complexity module found",
            new Dictionary<string, string>
            {
                ["expectedModules"] = "pam_pwquality.so, pam_cracklib.so, or pam_passwdqc.so"
            }, CisMappings);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.ShadowEntries.Count == 0 || data.UserAccounts.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

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
                    }, CisMappings);
            }

            if (shadow.ExpireDate.HasValue && shadow.ExpireDate.Value < todayDays)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} account expired",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["reason"] = "account expiry date has passed"
                    }, CisMappings);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.UserAccounts.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

        var groups = data.UserAccounts.GroupBy(a => a.Uid).Where(g => g.Count() > 1).ToList();
        if (groups.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings);

        var first = groups[0];
        var names = string.Join(", ", first.Select(a => a.Username));

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"UID {first.Key}: {names}",
            new Dictionary<string, string>
            {
                ["uid"] = first.Key.ToString(),
                ["usernames"] = names
            }, CisMappings);
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
                    }, CisMappings);
            }

            if (!account.HomeDirectoryExists)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{account.Username} home directory missing: {account.HomeDirectory}",
                    new Dictionary<string, string>
                    {
                        ["username"] = account.Username,
                        ["homeDirectory"] = account.HomeDirectory
                    }, CisMappings);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings);
    }

    private static bool IsInteractiveShell(string shell)
    {
        return !shell.Equals("/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/bin/false", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/sbin/nologin", StringComparison.OrdinalIgnoreCase)
               && !shell.Equals("/usr/sbin/nologin", StringComparison.OrdinalIgnoreCase);
    }
}
