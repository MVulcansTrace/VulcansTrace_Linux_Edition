using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class FilePermissionMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1222", TechniqueName = "File and Directory Permissions Modification", Tactic = "Defense Evasion", WhyItMatters = "Overly permissive files enable unauthorized access and permission abuse." },
    };
}


/// <summary>
/// FILE-001: /etc/shadow should have restrictive permissions.
/// </summary>
public sealed class ShadowPermissionRule : IRule
{
    public string Id => "FILE-001";
    public string Category => "FilePermission";
    public string Description => "/etc/shadow should be 640 or 600 and owned by root";
    public string WhatItChecks => "Checks whether /etc/shadow has overly permissive permissions or wrong ownership";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "The shadow file contains password hashes. World-readable or group-writable permissions expose credentials to offline cracking. CIS benchmarks require 640 with root ownership.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.1 — Ensure permissions on /etc/shadow are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entry = data.FilePermissions.FirstOrDefault(f =>
            f.Path.Equals("/etc/shadow", StringComparison.OrdinalIgnoreCase));

        if (entry == null || !entry.Exists)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!int.TryParse(entry.Mode, out var mode))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var isRootOwned = entry.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);
        var validGroup = entry.Group.Equals("root", StringComparison.OrdinalIgnoreCase)
                         || entry.Group.Equals("shadow", StringComparison.OrdinalIgnoreCase)
                         || entry.Group.Equals("sys", StringComparison.OrdinalIgnoreCase);

        // Accept 600 or 640
        if ((mode == 600 || mode == 640) && isRootOwned && validGroup)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"/etc/shadow {entry.Mode} {entry.Owner}:{entry.Group}",
            new Dictionary<string, string>
            {
                ["path"] = entry.Path,
                ["mode"] = entry.Mode,
                ["owner"] = entry.Owner,
                ["group"] = entry.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FILE-002: /etc/passwd should have correct permissions.
/// </summary>
public sealed class PasswdPermissionRule : IRule
{
    public string Id => "FILE-002";
    public string Category => "FilePermission";
    public string Description => "/etc/passwd should be 644 and owned by root";
    public string WhatItChecks => "Checks whether /etc/passwd has overly permissive permissions or wrong ownership";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "/etc/passwd maps usernames to UIDs and home directories. Writable by non-root users enables account manipulation and privilege escalation.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.2 — Ensure permissions on /etc/passwd are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entry = data.FilePermissions.FirstOrDefault(f =>
            f.Path.Equals("/etc/passwd", StringComparison.OrdinalIgnoreCase));

        if (entry == null || !entry.Exists)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!int.TryParse(entry.Mode, out var mode))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var isRootOwned = entry.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);
        var isRootGroup = entry.Group.Equals("root", StringComparison.OrdinalIgnoreCase);

        if (mode == 644 && isRootOwned && isRootGroup)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"/etc/passwd {entry.Mode} {entry.Owner}:{entry.Group}",
            new Dictionary<string, string>
            {
                ["path"] = entry.Path,
                ["mode"] = entry.Mode,
                ["owner"] = entry.Owner,
                ["group"] = entry.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FILE-003: SSH host private keys should be tightly restricted.
/// </summary>
public sealed class SshHostKeyPermissionRule : IRule
{
    public string Id => "FILE-003";
    public string Category => "FilePermission";
    public string Description => "SSH host private keys should be 600 and owned by root";
    public string WhatItChecks => "Checks whether /etc/ssh/ssh_host_*_key private keys have overly permissive permissions";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2",
            ControlName = "Use Unique Passwords",
            WhyItMatters = "Host private keys authenticate the server to clients. Readable by non-root users enables MITM attacks and host impersonation.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.2 — Ensure permissions on SSH private host key files are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var hostKeys = data.FilePermissions
            .Where(f => f.Path.StartsWith("/etc/ssh/ssh_host_", StringComparison.OrdinalIgnoreCase)
                        && !f.Path.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)
                        && f.Exists)
            .ToList();

        if (hostKeys.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        foreach (var entry in hostKeys)
        {
            if (!int.TryParse(entry.Mode, out var mode))
                continue;

            var isRootOwned = entry.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);

            if (mode != 600 || !isRootOwned)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{entry.Path} {entry.Mode} {entry.Owner}:{entry.Group}",
                    new Dictionary<string, string>
                    {
                        ["path"] = entry.Path,
                        ["mode"] = entry.Mode,
                        ["owner"] = entry.Owner,
                        ["group"] = entry.Group
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FILE-004: Root SSH directory and authorized_keys should be tightly restricted.
/// </summary>
public sealed class RootSshDirectoryPermissionRule : IRule
{
    public string Id => "FILE-004";
    public string Category => "FilePermission";
    public string Description => "/root/.ssh should be 700 and authorized_keys 600";
    public string WhatItChecks => "Checks whether the root SSH directory and authorized_keys file have overly permissive permissions";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2",
            ControlName = "Use Unique Passwords",
            WhyItMatters = "The root authorized_keys file grants password-less root access. World-readable or writable permissions allow credential theft or unauthorized key injection.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.4 — Ensure permissions on SSH public host key files are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var sshDir = data.FilePermissions.FirstOrDefault(f =>
            f.Path.Equals("/root/.ssh", StringComparison.OrdinalIgnoreCase));
        var authKeys = data.FilePermissions.FirstOrDefault(f =>
            f.Path.Equals("/root/.ssh/authorized_keys", StringComparison.OrdinalIgnoreCase));

        if (sshDir != null && sshDir.Exists)
        {
            if (int.TryParse(sshDir.Mode, out var dirMode))
            {
                var isRootOwned = sshDir.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);
                if (dirMode != 700 || !isRootOwned)
                {
                    return RuleResult.Fail(Id, Category, Id, Description, Severity,
                        $"/root/.ssh {sshDir.Mode} {sshDir.Owner}:{sshDir.Group}",
                        new Dictionary<string, string>
                        {
                            ["path"] = sshDir.Path,
                            ["mode"] = sshDir.Mode,
                            ["owner"] = sshDir.Owner,
                            ["group"] = sshDir.Group
                        }, CisMappings, MitreTechniques);
                }
            }
        }

        if (authKeys != null && authKeys.Exists)
        {
            if (int.TryParse(authKeys.Mode, out var fileMode))
            {
                var isRootOwned = authKeys.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);
                if (fileMode != 600 || !isRootOwned)
                {
                    return RuleResult.Fail(Id, Category, Id, Description, Severity,
                        $"/root/.ssh/authorized_keys {authKeys.Mode} {authKeys.Owner}:{authKeys.Group}",
                        new Dictionary<string, string>
                        {
                            ["path"] = authKeys.Path,
                            ["mode"] = authKeys.Mode,
                            ["owner"] = authKeys.Owner,
                            ["group"] = authKeys.Group
                        }, CisMappings, MitreTechniques);
                }
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FILE-005: Cron directories should not be world-writable.
/// </summary>
public sealed class CronDirectoryWorldWritableRule : IRule
{
    public string Id => "FILE-005";
    public string Category => "FilePermission";
    public string Description => "Cron directories should not be world-writable";
    public string WhatItChecks => "Checks whether cron directories allow write access to everyone";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "World-writable cron directories allow any user to inject scheduled jobs, leading to privilege escalation and persistent backdoors.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.3 — Ensure permissions on /etc/cron.* are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var cronDirs = data.FilePermissions
            .Where(f => f.Exists && IsCronDirectory(f.Path))
            .ToList();

        if (cronDirs.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        foreach (var entry in cronDirs)
        {
            if (!int.TryParse(entry.Mode, out var mode))
                continue;

            // World-writable: last octal digit >= 2 and has write bit (2)
            // In octal, last digit: 2,3,6,7 are world-writable
            var lastDigit = mode % 10;
            if (lastDigit is 2 or 3 or 6 or 7)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{entry.Path} {entry.Mode} {entry.Owner}:{entry.Group}",
                    new Dictionary<string, string>
                    {
                        ["path"] = entry.Path,
                        ["mode"] = entry.Mode,
                        ["owner"] = entry.Owner,
                        ["group"] = entry.Group
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool IsCronDirectory(string path)
    {
        return path.StartsWith("/etc/cron", StringComparison.OrdinalIgnoreCase)
               || path.StartsWith("/var/spool/cron", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// FILE-006: /etc/crontab should have correct permissions.
/// </summary>
public sealed class CrontabPermissionRule : IRule
{
    public string Id => "FILE-006";
    public string Category => "FilePermission";
    public string Description => "/etc/crontab should be 644 or 600 and owned by root";
    public string WhatItChecks => "Checks whether /etc/crontab has overly permissive permissions or wrong ownership";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "/etc/crontab defines system-wide scheduled tasks. Writable by non-root users allows arbitrary code execution with elevated privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.4 — Ensure permissions on /etc/crontab are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entry = data.FilePermissions.FirstOrDefault(f =>
            f.Path.Equals("/etc/crontab", StringComparison.OrdinalIgnoreCase));

        if (entry == null || !entry.Exists)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!int.TryParse(entry.Mode, out var mode))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var isRootOwned = entry.Owner.Equals("root", StringComparison.OrdinalIgnoreCase);
        var isRootGroup = entry.Group.Equals("root", StringComparison.OrdinalIgnoreCase);

        if ((mode == 644 || mode == 600) && isRootOwned && isRootGroup)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"/etc/crontab {entry.Mode} {entry.Owner}:{entry.Group}",
            new Dictionary<string, string>
            {
                ["path"] = entry.Path,
                ["mode"] = entry.Mode,
                ["owner"] = entry.Owner,
                ["group"] = entry.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FILE-007: User SSH directories and authorized_keys should be tightly restricted.
/// </summary>
public sealed class UserSshDirectoryPermissionRule : IRule
{
    public string Id => "FILE-007";
    public string Category => "FilePermission";
    public string Description => "User SSH directories and authorized_keys should be tightly restricted";
    public string WhatItChecks => "Checks whether user ~/.ssh directories and authorized_keys files have overly permissive permissions";
    public IReadOnlyList<string> SupportedDataSources => new[] { "stat" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2",
            ControlName = "Use Unique Passwords",
            WhyItMatters = "User SSH keys grant password-less access. World-readable or writable permissions allow credential theft or unauthorized key injection.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.4 — Ensure permissions on SSH public host key files are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilePermissionMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var userSshEntries = data.FilePermissions
            .Where(f => f.Exists && f.Path.StartsWith("/home/", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (userSshEntries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        foreach (var entry in userSshEntries)
        {
            if (!int.TryParse(entry.Mode, out var mode))
                continue;

            var isDir = !entry.Path.EndsWith("authorized_keys", StringComparison.OrdinalIgnoreCase);
            var expectedMode = isDir ? 700 : 600;

            if (mode != expectedMode)
            {
                return RuleResult.Fail(Id, Category, Id, Description, Severity,
                    $"{entry.Path} {entry.Mode} {entry.Owner}:{entry.Group}",
                    new Dictionary<string, string>
                    {
                        ["path"] = entry.Path,
                        ["mode"] = entry.Mode,
                        ["owner"] = entry.Owner,
                        ["group"] = entry.Group
                    }, CisMappings, MitreTechniques);
            }
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }
}
