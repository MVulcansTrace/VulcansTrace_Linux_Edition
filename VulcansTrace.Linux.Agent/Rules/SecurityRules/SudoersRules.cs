using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class SudoersMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique
        {
            TechniqueId = "T1548.003",
            TechniqueName = "Sudo and Sudo Caching",
            Tactic = "Privilege Escalation",
            WhyItMatters = "Overly permissive sudoers configuration allows attackers to escalate privileges without re-authentication."
        },
        new MitreTechnique
        {
            TechniqueId = "T1078",
            TechniqueName = "Valid Accounts",
            Tactic = "Initial Access",
            WhyItMatters = "Broad sudo grants turn compromised user accounts into full administrative access."
        }
    };
}

/// <summary>
/// SUDO-001: /etc/sudoers should be writable only by root and readable by root/sudo group.
/// </summary>
public sealed class SudoersFilePermissionRule : IRule
{
    public string Id => "SUDO-001";
    public string Category => "Sudoers";
    public string Description => "/etc/sudoers should have restrictive permissions (0440) and be owned by root";
    public string WhatItChecks => "Checks whether /etc/sudoers is owned by root, not writable by group/others, and not world-readable";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/sudoers", "stat" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.8",
            ControlName = "Define and Maintain Role-Based Access Control",
            WhyItMatters = "World-writable or group-writable sudoers files allow any user to grant themselves root privileges. CIS benchmarks require /etc/sudoers to be owned by root with mode 0440.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.1 — Ensure sudo is installed"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SudoersMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SudoersConfig == null || !data.SudoersConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var mode = data.SudoersConfig.MainFileMode;
        var owner = data.SudoersConfig.MainFileOwner;

        if (string.IsNullOrWhiteSpace(mode))
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        if (InsecureSudoersMode(mode, out var reason))
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity.Critical,
                $"/etc/sudoers mode {mode} ({reason})",
                new Dictionary<string, string> { ["mode"] = mode, ["owner"] = owner ?? "unknown" },
                CisMappings, MitreTechniques);
        }

        if (!string.IsNullOrWhiteSpace(owner) && !owner.Equals("root", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity.Critical,
                $"/etc/sudoers owner {owner}",
                new Dictionary<string, string> { ["mode"] = mode, ["owner"] = owner },
                CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    /// <summary>
    /// /etc/sudoers must grant write access only to root. Fail when the mode is group- or
    /// other-writable (anyone could inject a privilege grant), world-readable (non-compliant
    /// and rejected by sudo itself), or simply unparseable as octal. The canonical mode is 0440.
    /// </summary>
    private static bool InsecureSudoersMode(string mode, out string reason)
    {
        reason = "";
        if (!TryParseOctalMode(mode.Trim(), out int bits))
        {
            reason = "unparseable mode";
            return true;
        }

        const int GroupWriteBit = 16; // 0o020
        const int OtherWriteBit = 2;  // 0o002
        const int OtherReadBit = 4;   // 0o004

        if ((bits & GroupWriteBit) != 0)
        {
            reason = "group-writable";
            return true;
        }
        if ((bits & OtherWriteBit) != 0)
        {
            reason = "world-writable";
            return true;
        }
        if ((bits & OtherReadBit) != 0)
        {
            reason = "world-readable";
            return true;
        }
        return false;
    }

    private static bool TryParseOctalMode(string value, out int bits)
    {
        bits = 0;
        if (value.Length == 0)
            return false;
        // `stat -c '%a'` emits the permission bits only — the setuid/setgid/sticky
        // nibble plus the three rwx triples — so the value is at most 0o7777. Leading
        // zeros (the human convention "0440", or "04000" for a setuid file) don't
        // change the value and are accepted; a value above 0o7777 carries file-type
        // bits (a raw st_mode such as 0o100440), which %a never emits, so reject it
        // rather than misread it. Bailing as soon as the accumulator exceeds 0o7777
        // also bounds it and avoids int overflow on long garbage input.
        foreach (var ch in value)
        {
            if (ch < '0' || ch > '7')
                return false;
            bits = bits * 8 + (ch - '0');
            if (bits > 4095) // 0o7777
                return false;
        }
        return true;
    }
}

/// <summary>
/// SUDO-002: No user or group should have passwordless full sudo (NOPASSWD: ALL).
/// </summary>
public sealed class SudoersNoPasswordlessFullSudoRule : IRule
{
    public string Id => "SUDO-002";
    public string Category => "Sudoers";
    public string Description => "Passwordless full sudo (NOPASSWD: ALL) should not be granted";
    public string WhatItChecks => "Checks whether any user or group can run any command as any user without a password";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/sudoers", "/etc/sudoers.d" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.8",
            ControlName = "Define and Maintain Role-Based Access Control",
            WhyItMatters = "NOPASSWD bypasses authentication for privileged execution. A compromised account with passwordless sudo can escalate to root instantly, breaking accountability and enabling lateral movement.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.3 — Ensure sudo authentication timeout is configured"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SudoersMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SudoersConfig == null || !data.SudoersConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!data.SudoersConfig.HasPasswordlessFullSudo)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var offenders = data.SudoersConfig.Entries
            .Where(e => SudoersScanner.IsFullSudoEntry(e) && e.NoPasswd)
            .Select(e => e.Principal)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return RuleResult.Fail(Id, Category, Id, Description, Severity.Critical,
            $"Passwordless full sudo granted to {string.Join(", ", offenders)}",
            new Dictionary<string, string> { ["principals"] = string.Join(",", offenders) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// SUDO-003: Avoid granting full sudo (ALL=(ALL:ALL) ALL) when more restrictive commands would suffice.
/// </summary>
public sealed class SudoersFullSudoRule : IRule
{
    public string Id => "SUDO-003";
    public string Category => "Sudoers";
    public string Description => "Full sudo (ALL=(ALL:ALL) ALL) should be limited to trusted break-glass accounts";
    public string WhatItChecks => "Checks whether any user or group is granted unrestricted sudo privileges";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/sudoers", "/etc/sudoers.d" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.8",
            ControlName = "Define and Maintain Role-Based Access Control",
            WhyItMatters = "Granting ALL to every administrator removes least-privilege separation. Restrict sudo to explicit commands per role to limit blast radius from credential compromise.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.2 — Ensure sudo commands use pty and log"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SudoersMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SudoersConfig == null || !data.SudoersConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!data.SudoersConfig.HasFullSudo)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var offenders = data.SudoersConfig.Entries
            .Where(SudoersScanner.IsFullSudoEntry)
            .Select(e => e.Principal)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return RuleResult.Fail(Id, Category, Id, Description, Severity.High,
            $"Full sudo granted to {string.Join(", ", offenders)}",
            new Dictionary<string, string> { ["principals"] = string.Join(",", offenders) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// SUDO-004: Defaults !authenticate disables password prompts for sudo.
/// </summary>
public sealed class SudoersNoAuthenticateRule : IRule
{
    public string Id => "SUDO-004";
    public string Category => "Sudoers";
    public string Description => "sudo authentication should not be disabled globally with !authenticate";
    public string WhatItChecks => "Checks whether Defaults !authenticate is set";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/sudoers", "/etc/sudoers.d" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.8",
            ControlName = "Define and Maintain Role-Based Access Control",
            WhyItMatters = "Disabling sudo authentication removes the primary control protecting privileged execution. This is equivalent to passwordless root access for any account with sudo privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.3 — Ensure sudo authentication timeout is configured"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SudoersMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SudoersConfig == null || !data.SudoersConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!data.SudoersConfig.HasNoAuthenticate)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity.Critical,
            "Defaults !authenticate detected",
            new Dictionary<string, string> { ["setting"] = "!authenticate" },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// SUDO-005: secure_path should be configured to avoid PATH manipulation attacks.
/// </summary>
public sealed class SudoersSecurePathRule : IRule
{
    public string Id => "SUDO-005";
    public string Category => "Sudoers";
    public string Description => "sudo secure_path should be configured";
    public string WhatItChecks => "Checks whether Defaults secure_path is set in sudoers";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/sudoers", "/etc/sudoers.d" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.8",
            ControlName = "Define and Maintain Role-Based Access Control",
            WhyItMatters = "Without secure_path, sudo inherits the caller's PATH, allowing attackers to plant malicious binaries in writable directories and have them executed with elevated privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.4 — Ensure sudo log file exists"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SudoersMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SudoersConfig == null || !data.SudoersConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (data.SudoersConfig.HasSecurePath)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity.Medium,
            "Defaults secure_path is not configured",
            new Dictionary<string, string> { ["setting"] = "secure_path" },
            CisMappings, MitreTechniques);
    }
}
