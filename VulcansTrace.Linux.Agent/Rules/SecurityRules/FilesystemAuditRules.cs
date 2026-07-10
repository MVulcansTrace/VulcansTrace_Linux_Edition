using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class FilesystemAuditMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1083", TechniqueName = "File and Directory Discovery", Tactic = "Discovery", WhyItMatters = "Filesystem misconfigurations enable unauthorized file and directory discovery." },
        new MitreTechnique { TechniqueId = "T1222", TechniqueName = "File and Directory Permissions Modification", Tactic = "Defense Evasion", WhyItMatters = "World-writable files and directories weaken permission boundaries, enabling attackers to modify, replace, or hide malicious content." },
    };
}


/// <summary>
/// FSYS-001: World-writable files outside expected temporary paths.
/// </summary>
public sealed class WorldWritableFileRule : IRule
{
    public string Id => "FSYS-001";
    public string Category => FindingCategories.FilesystemAudit;
    public string Description => "World-writable files outside expected temporary paths";
    public string WhatItChecks => "Checks for world-writable files outside /tmp, /var/tmp, /dev/shm, and other expected paths";
    public IReadOnlyList<string> SupportedDataSources => new[] { "find-world-writable-files" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1.9",
            ControlName = "Ensure no world writable files exist",
            WhyItMatters = "World-writable files allow any user to modify their contents. Outside temporary directories, this is often a misconfiguration or a persistence vector for attackers.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.9 — Ensure no world writable files exist"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilesystemAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entries = data.FilesystemAudits
            .Where(e => e.AuditCategory == "WorldWritableFile")
            .OrderBy(e => e.Path, StringComparer.Ordinal)
            .ToList();

        if (entries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = entries.First();
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            first.Path,
            new Dictionary<string, string>
            {
                ["count"] = entries.Count.ToString(),
                ["path"] = first.Path,
                ["mode"] = first.Mode,
                ["owner"] = first.Owner,
                ["group"] = first.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FSYS-002: Unexpected SUID/SGID binaries.
/// </summary>
public sealed class UnexpectedSuidSgidRule : IRule
{
    public string Id => "FSYS-002";
    public string Category => FindingCategories.FilesystemAudit;
    public string Description => "Unexpected SUID/SGID binaries";
    public string WhatItChecks => "Checks for SUID/SGID binaries outside standard system directories or not matching the known-good full-path whitelist";
    public IReadOnlyList<string> SupportedDataSources => new[] { "find-suid-sgid" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1.12",
            ControlName = "Ensure SUID and SGID files are reviewed",
            WhyItMatters = "SUID/SGID binaries execute with elevated privileges. Unexpected ones are a classic privilege-escalation vector and may indicate a backdoor or incomplete cleanup.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.12 — Ensure SUID and SGID files are reviewed"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilesystemAuditMitreMappings.Techniques;

    // Whitelist is by FULL PATH, not just filename. Binaries must reside in standard system directories.
    private static readonly HashSet<string> ExpectedSuidPaths = new(StringComparer.Ordinal)
    {
        "/usr/bin/sudo", "/bin/sudo", "/usr/bin/su", "/bin/su",
        "/usr/bin/passwd", "/bin/passwd", "/usr/bin/mount", "/bin/mount",
        "/usr/bin/umount", "/bin/umount", "/usr/bin/ping", "/bin/ping",
        "/usr/bin/ping6", "/bin/ping6", "/usr/bin/newgrp", "/bin/newgrp",
        "/usr/bin/chsh", "/bin/chsh", "/usr/bin/chfn", "/bin/chfn",
        "/usr/bin/pkexec", "/usr/bin/sg", "/usr/bin/fusermount",
        "/usr/bin/fusermount3", "/usr/bin/ntfs-3g", "/usr/bin/newuidmap",
        "/usr/bin/newgidmap", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/policykit-1/polkit-agent-helper-1", "/usr/lib/polkit-1/polkit-agent-helper-1",
        "/usr/bin/crontab", "/bin/crontab", "/usr/bin/at", "/bin/at",
        "/usr/bin/chage", "/bin/chage", "/usr/bin/gpasswd", "/bin/gpasswd",
        "/usr/sbin/unix_chkpwd", "/usr/bin/ssh-agent", "/usr/bin/sudoedit",
        "/usr/lib/snapd/snap-confine", "/usr/lib/snapd/snap-update-ns",
        "/usr/bin/bwrap", "/usr/bin/flatpak-bwrap", "/usr/bin/runuser",
        "/usr/bin/cockpit-session", "/usr/bin/quota", "/usr/bin/rpcinfo",
        "/usr/bin/traceroute6", "/usr/bin/traceroute6.iputils",
        "/usr/bin/arping", "/usr/bin/clockdiff", "/usr/bin/mtr",
        "/usr/bin/mtr-packet", "/usr/bin/uuidd", "/usr/sbin/vigr",
        "/usr/sbin/vipw", "/usr/bin/expiry", "/usr/bin/write",
        "/usr/bin/wall", "/usr/sbin/usermod", "/usr/sbin/useradd",
        "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/sbin/pam_timestamp_check",
        "/usr/lib/pt_chown", "/usr/bin/Xorg", "/usr/bin/X",
        "/usr/sbin/lightdm", "/usr/bin/smbmnt", "/usr/bin/smbumount",
        "/usr/bin/ecryptfs-mount-private", "/usr/bin/mount.ecryptfs_private",
        "/usr/bin/vmware-user-suid-wrapper", "/usr/sbin/usernetctl",
        "/usr/sbin/userhelper", "/usr/bin/suexec", "/usr/bin/start-stop-daemon",
        "/usr/bin/tcpdump", "/usr/bin/screen", "/usr/bin/rsync",
        "/usr/bin/procmail", "/usr/sbin/pptp", "/usr/sbin/nfnl_osf",
        "/usr/sbin/kerneloops", "/usr/bin/iputils-ping", "/usr/bin/iputils-arping",
        "/usr/bin/iputils-clockdiff", "/usr/bin/iputils-tracepath",
        "/usr/bin/unix2tcp", "/usr/bin/rsh", "/usr/bin/rlogin",
        "/usr/bin/rcp", "/usr/bin/rsh-redone-rsh", "/usr/bin/rsh-redone-rlogin",
        "/usr/bin/mail-lock", "/usr/bin/mail-unlock", "/usr/bin/mailq",
        "/usr/bin/lpr", "/usr/bin/lprm", "/usr/bin/lpc", "/usr/sbin/lpd",
        "/usr/bin/grub-mount", "/usr/bin/zzz", "/usr/bin/zzz-static",
        "/usr/bin/xtrlock", "/usr/bin/xscreensaver", "/usr/bin/xfs",
        "/usr/bin/xdm", "/usr/bin/xconsole", "/usr/bin/xlock",
        "/usr/bin/weston-launch", "/usr/bin/vlock", "/usr/bin/vmstat",
        "/usr/bin/w", "/usr/bin/tdbdump", "/usr/bin/tdbtool",
        "/usr/bin/savelog", "/usr/bin/run-mailcap", "/usr/bin/sash",
        "/usr/bin/rvcat", "/usr/bin/psm", "/usr/bin/opieinfo",
        "/usr/bin/opiepasswd", "/usr/bin/ntfsmount", "/usr/bin/locate",
        "/usr/bin/cu", "/usr/bin/ct", "/usr/bin/cmd", "/usr/bin/uucp",
        "/usr/bin/uuname", "/usr/bin/uustat", "/usr/bin/uux", "/usr/bin/tip"
    };

    public RuleResult Evaluate(ScanData data)
    {
        var entries = data.FilesystemAudits
            .Where(e => e.AuditCategory is "SuidBinary" or "SgidBinary" or "SuidSgidBinary")
            .OrderBy(e => e.Path, StringComparer.Ordinal)
            .ToList();

        if (entries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var unexpected = entries.Where(e => !IsExpected(e.Path)).ToList();
        if (unexpected.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = unexpected.First();
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            first.Path,
            new Dictionary<string, string>
            {
                ["count"] = unexpected.Count.ToString(),
                ["path"] = first.Path,
                ["mode"] = first.Mode,
                ["owner"] = first.Owner,
                ["group"] = first.Group
            }, CisMappings, MitreTechniques);
    }

    private static bool IsExpected(string path)
    {
        return ExpectedSuidPaths.Contains(path);
    }
}

/// <summary>
/// FSYS-003: Unowned files.
/// </summary>
public sealed class UnownedFileRule : IRule
{
    public string Id => "FSYS-003";
    public string Category => FindingCategories.FilesystemAudit;
    public string Description => "Unowned files exist on the filesystem";
    public string WhatItChecks => "Checks for files whose owner or group does not map to a valid user or group";
    public IReadOnlyList<string> SupportedDataSources => new[] { "find-unowned-files" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1.11",
            ControlName = "Ensure no unowned files or directories exist",
            WhyItMatters = "Unowned files may be left behind after user deletion, package corruption, or attacker activity. They complicate accountability and can hide malicious content.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.11 — Ensure no unowned files or directories exist"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilesystemAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entries = data.FilesystemAudits
            .Where(e => e.AuditCategory == "UnownedFile")
            .OrderBy(e => e.Path, StringComparer.Ordinal)
            .ToList();

        if (entries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = entries.First();
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            first.Path,
            new Dictionary<string, string>
            {
                ["count"] = entries.Count.ToString(),
                ["path"] = first.Path,
                ["mode"] = first.Mode,
                ["owner"] = first.Owner,
                ["group"] = first.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FSYS-004: World-writable directories without sticky bit.
/// </summary>
public sealed class WorldWritableDirNoStickyRule : IRule
{
    public string Id => "FSYS-004";
    public string Category => FindingCategories.FilesystemAudit;
    public string Description => "World-writable directories without sticky bit";
    public string WhatItChecks => "Checks for world-writable directories that do not have the sticky bit set";
    public IReadOnlyList<string> SupportedDataSources => new[] { "find-world-writable-dirs" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1.10",
            ControlName = "Ensure sticky bit is set on all world-writable directories",
            WhyItMatters = "Without the sticky bit, any user can delete or rename files in a world-writable directory regardless of ownership. The sticky bit restricts deletion to the file owner, root, or the directory owner.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.10 — Ensure sticky bit is set on all world-writable directories"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilesystemAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entries = data.FilesystemAudits
            .Where(e => e.AuditCategory == "WorldWritableDirNoSticky")
            .OrderBy(e => e.Path, StringComparer.Ordinal)
            .ToList();

        if (entries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = entries.First();
        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            first.Path,
            new Dictionary<string, string>
            {
                ["count"] = entries.Count.ToString(),
                ["path"] = first.Path,
                ["mode"] = first.Mode,
                ["owner"] = first.Owner,
                ["group"] = first.Group
            }, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// FSYS-005: /tmp not mounted with noexec, nosuid, and nodev.
/// </summary>
public sealed class TmpHardeningRule : IRule
{
    public string Id => "FSYS-005";
    public string Category => FindingCategories.FilesystemAudit;
    public string Description => "/tmp should be mounted with noexec, nosuid, and nodev";
    public string WhatItChecks => "Checks whether /tmp is a separate mount with restrictive options that prevent execution and device creation";
    public IReadOnlyList<string> SupportedDataSources => new[] { "findmnt-tmp" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "The /tmp directory is world-writable and frequently used by attackers to stage payloads. Mounting it with noexec, nosuid, and nodev limits what can be run or elevated from that location. CIS also recommends /tmp be a separate partition.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.1.2.2-4 — Ensure nodev, nosuid, noexec options set on /tmp partition"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FilesystemAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        // If we couldn't determine the mount target or options at all, pass (data unavailable).
        if (string.IsNullOrWhiteSpace(data.TmpMountTarget) && string.IsNullOrWhiteSpace(data.TmpMountOptions))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        // CIS recommends /tmp be a separate partition. If it's on the root filesystem, flag it.
        if (!string.IsNullOrWhiteSpace(data.TmpMountTarget) &&
            !data.TmpMountTarget.Equals("/tmp", StringComparison.Ordinal))
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity,
                $"/tmp is not a separate mount (mounted on {data.TmpMountTarget})",
                new Dictionary<string, string>
                {
                    ["target"] = data.TmpMountTarget,
                    ["options"] = data.TmpMountOptions
                }, CisMappings, MitreTechniques);
        }

        if (string.IsNullOrWhiteSpace(data.TmpMountOptions))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var options = data.TmpMountOptions.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(o => o.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missing = new List<string>();
        if (!options.Contains("noexec")) missing.Add("noexec");
        if (!options.Contains("nosuid")) missing.Add("nosuid");
        if (!options.Contains("nodev")) missing.Add("nodev");

        if (missing.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"/tmp missing mount options: {string.Join(", ", missing)}",
            new Dictionary<string, string>
            {
                ["options"] = data.TmpMountOptions,
                ["missing"] = string.Join(", ", missing)
            }, CisMappings, MitreTechniques);
    }
}
