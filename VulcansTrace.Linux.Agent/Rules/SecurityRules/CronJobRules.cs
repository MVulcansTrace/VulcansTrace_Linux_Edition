using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Extensions;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class CronJobMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1053", TechniqueName = "Scheduled Task/Job", Tactic = "Persistence", WhyItMatters = "Cron is a common persistence mechanism for attackers." },
        new MitreTechnique { TechniqueId = "T1053.003", TechniqueName = "Scheduled Task/Job: Cron", Tactic = "Persistence", WhyItMatters = "Malicious cron entries establish persistent execution on Linux systems." },
    };
}


/// <summary>
/// CRON-001: Suspicious cron entries (reverse shells, network tools, temp paths, encoded payloads).
/// </summary>
public sealed class SuspiciousCronEntryRule : IRule
{
    public string Id => "CRON-001";
    public string Category => FindingCategories.CronJob;
    public string Description => "Cron entries should not contain suspicious commands";
    public string WhatItChecks => "Checks cron jobs for suspicious patterns such as reverse shells, network downloaders, temporary paths, and encoded payloads";
    public IReadOnlyList<string> SupportedDataSources => new[] { "crontab", "cron.d", "user crontabs", "cron scripts" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "Malicious cron entries are a common persistence mechanism. Attackers use cron to re-establish access, exfiltrate data, or execute backdoors with elevated privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.3 — Ensure permissions on /etc/cron.* are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => CronJobMitreMappings.Techniques;

    // Patterns that indicate potentially malicious cron commands.
    // Patterns containing /, space, (, or . are matched as substrings.
    // Simple words are matched with word-boundary awareness to reduce false positives.
    private static readonly string[] SuspiciousPatterns =
    {
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "wget", "curl", "nc", "netcat", "ncat",
        "bash -i", "sh -i", "zsh -i",
        "python -c", "perl -e", "ruby -e", "php -r",
        "/dev/tcp/", "/dev/udp/",
        "mkfifo",
        "openssl s_client",
        "eval(",
        "pty.spawn",
        "socket.socket",
        "subprocess.call",
        "os.system("
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!HasCronDataAvailable(data))
            return NotApplicableResult();

        var violations = new List<(CronJobEntry Entry, string Pattern)>();

        foreach (var entry in data.CronJobs)
        {
            foreach (var pattern in SuspiciousPatterns)
            {
                if (IsWordMatch(entry.Command, pattern))
                    violations.Add((entry, pattern));
            }
        }

        if (violations.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = violations[0];
        var target = $"{violations.Count} suspicious entr{(violations.Count == 1 ? "y" : "ies")}: " +
            string.Join("; ", violations.Select(v => $"{v.Entry.SourceFile}: {v.Entry.Command} ({v.Pattern})"));

        target = target.TruncateWithEllipsis(500);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            target,
            new Dictionary<string, string>
            {
                ["count"] = violations.Count.ToString(),
                ["firstSource"] = first.Entry.SourceFile,
                ["firstCommand"] = first.Entry.Command,
                ["firstPattern"] = first.Pattern
            }, CisMappings, MitreTechniques);
    }

    /// <summary>
    /// Checks whether <paramref name="pattern"/> matches within <paramref name="command"/>
    /// with word-boundary awareness for simple words.
    /// </summary>
    internal static bool IsWordMatch(string command, string pattern)
    {
        // Patterns that contain path separators, spaces, or special chars are matched literally
        if (pattern.Contains('/') || pattern.Contains(' ') || pattern.Contains('(') || pattern.Contains('.'))
            return command.Contains(pattern, StringComparison.OrdinalIgnoreCase);

        var idx = 0;
        while (idx < command.Length)
        {
            var found = command.IndexOf(pattern, idx, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
                return false;

            // Preceding char must be start-of-string or non-word-char
            var prevOk = found == 0 || !IsWordChar(command[found - 1]);

            // Following char must be end-of-string or non-word-char
            var after = found + pattern.Length;
            var nextOk = after >= command.Length || !IsWordChar(command[after]);

            if (prevOk && nextOk)
                return true;

            idx = found + 1;
        }

        return false;
    }

    private static bool IsWordChar(char c) => char.IsLetterOrDigit(c) || c == '_';

    private static bool HasCronDataAvailable(ScanData data)
    {
        // If there are actual cron jobs, data was clearly available
        if (data.CronJobs.Count > 0)
            return true;

        // Otherwise check if any cron scanner capabilities were reported
        return data.Capabilities.Any(c =>
            c.SourceName.Equals("/etc/crontab", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.d", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/var/spool/cron", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.daily", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.hourly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.weekly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.monthly", StringComparison.OrdinalIgnoreCase));
    }

    private static RuleResult NotApplicableResult()
    {
        return new RuleResult
        {
            RuleId = "CRON-001",
            Category = FindingCategories.CronJob,
            Passed = true,
            Status = RuleStatus.NotApplicable,
            ExplanationKey = "CRON-001",
            Description = "Cron entries should not contain suspicious commands — No cron data available (requires root or cron files not present).",
            CisMappings = new[]
            {
                new CisBenchmarkMapping
                {
                    ControlId = "CIS 6.1",
                    ControlName = "Configure System File Permissions",
                    WhyItMatters = "Malicious cron entries are a common persistence mechanism. Attackers use cron to re-establish access, exfiltrate data, or execute backdoors with elevated privileges.",
                    BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.3 — Ensure permissions on /etc/cron.* are configured"
                }
            },
            MitreTechniques = CronJobMitreMappings.Techniques
        };
    }
}

/// <summary>
/// CRON-002: World-writable or setuid/setgid cron scripts.
/// </summary>
public sealed class WorldWritableCronScriptRule : IRule
{
    public string Id => "CRON-002";
    public string Category => FindingCategories.CronJob;
    public string Description => "Cron scripts should not be world-writable or have setuid/setgid bits";
    public string WhatItChecks => "Checks script files in cron.daily, cron.hourly, cron.weekly, and cron.monthly for world-writable permissions or dangerous setuid/setgid bits";
    public IReadOnlyList<string> SupportedDataSources => new[] { "cron scripts", "stat" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.1",
            ControlName = "Configure System File Permissions",
            WhyItMatters = "World-writable or setuid cron scripts allow any local user to modify scheduled tasks or escalate privileges. When cron executes the modified script, the attacker achieves arbitrary code execution with elevated privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.3 — Ensure permissions on /etc/cron.* are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => CronJobMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!HasCronDataAvailable(data))
            return NotApplicableResult();

        var worldWritable = new List<CronJobEntry>();
        var setuidSgid = new List<CronJobEntry>();

        foreach (var entry in data.CronJobs)
        {
            if (!entry.IsScript)
                continue;

            if (string.IsNullOrEmpty(entry.ScriptPermissions))
                continue;

            if (!int.TryParse(entry.ScriptPermissions, out var mode))
                continue;

            var lastDigit = mode % 10;
            if (lastDigit is 2 or 3 or 6 or 7)
                worldWritable.Add(entry);

            var upperDigit = mode / 1000;
            if (upperDigit is 2 or 3 or 4 or 5 or 6 or 7)
                setuidSgid.Add(entry);
        }

        var hasSetuid = setuidSgid.Count > 0;
        var hasWorldWritable = worldWritable.Count > 0;

        if (hasSetuid || hasWorldWritable)
        {
            var allViolations = setuidSgid.Concat(worldWritable).Distinct().ToList();
            var severity = hasSetuid ? Severity.Critical : Severity;
            var typeLabel = hasSetuid ? "setuid/setgid" : "world-writable";

            var target = $"{allViolations.Count} script{(allViolations.Count == 1 ? "" : "s")}: " +
                string.Join("; ", allViolations.Select(s => $"{s.SourceFile} {s.ScriptPermissions}"));

            target = target.TruncateWithEllipsis(500);

            return RuleResult.Fail(Id, Category, Id, Description, severity,
                target,
                new Dictionary<string, string>
                {
                    ["count"] = allViolations.Count.ToString(),
                    ["type"] = typeLabel
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
    }

    private static bool HasCronDataAvailable(ScanData data)
    {
        if (data.CronJobs.Count > 0)
            return true;

        return data.Capabilities.Any(c =>
            c.SourceName.Equals("/etc/crontab", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.d", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/var/spool/cron", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.daily", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.hourly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.weekly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.monthly", StringComparison.OrdinalIgnoreCase));
    }

    private static RuleResult NotApplicableResult()
    {
        return new RuleResult
        {
            RuleId = "CRON-002",
            Category = FindingCategories.CronJob,
            Passed = true,
            Status = RuleStatus.NotApplicable,
            ExplanationKey = "CRON-002",
            Description = "Cron scripts should not be world-writable or have setuid/setgid bits — No cron script data available (requires root or cron directories not present).",
            CisMappings = new[]
            {
                new CisBenchmarkMapping
                {
                    ControlId = "CIS 6.1",
                    ControlName = "Configure System File Permissions",
                    WhyItMatters = "World-writable or setuid cron scripts allow any local user to modify scheduled tasks or escalate privileges. When cron executes the modified script, the attacker achieves arbitrary code execution with elevated privileges.",
                    BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.1.3 — Ensure permissions on /etc/cron.* are configured"
                }
            },
            MitreTechniques = CronJobMitreMappings.Techniques
        };
    }
}

/// <summary>
/// CRON-003: Cron jobs running as root that reference non-root user paths.
/// </summary>
public sealed class RootCronForNonRootUserRule : IRule
{
    public string Id => "CRON-003";
    public string Category => FindingCategories.CronJob;
    public string Description => "Root cron jobs should not reference non-root user directories";
    public string WhatItChecks => "Checks system crontab entries running as root that reference paths under /home/ or other non-root user directories";
    public IReadOnlyList<string> SupportedDataSources => new[] { "crontab", "cron.d" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.2",
            ControlName = "Configure System Account Security",
            WhyItMatters = "System-wide cron jobs running as root should be system-wide. User-specific jobs should be placed in the user's own crontab. Root jobs referencing user directories may indicate privilege misuse or attacker persistence.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => CronJobMitreMappings.Techniques;

    // Match any /home/ reference
    private static readonly Regex HomePathRegex = new(
        @"/home/[^/\s]+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Match ~username expansions (tilde followed by a letter)
    private static readonly Regex TildeUserRegex = new(
        @"~[a-zA-Z]",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public RuleResult Evaluate(ScanData data)
    {
        if (!HasCronDataAvailable(data))
            return NotApplicableResult();

        var violations = new List<CronJobEntry>();

        foreach (var entry in data.CronJobs)
        {
            // Only evaluate system crontab entries running as root
            if (string.IsNullOrEmpty(entry.RunAsUser))
                continue;

            if (!entry.RunAsUser.Equals("root", StringComparison.OrdinalIgnoreCase))
                continue;

            if (ReferencesNonRootHomePath(entry.Command))
                violations.Add(entry);
        }

        if (violations.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = violations[0];
        var target = $"{violations.Count} root job{(violations.Count == 1 ? "" : "s")} reference user paths: " +
            string.Join("; ", violations.Select(v => $"{v.SourceFile}: {v.Command}"));

        target = target.TruncateWithEllipsis(500);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            target,
            new Dictionary<string, string>
            {
                ["count"] = violations.Count.ToString(),
                ["firstSource"] = first.SourceFile,
                ["firstCommand"] = first.Command,
                ["runAsUser"] = first.RunAsUser!
            }, CisMappings, MitreTechniques);
    }

    internal static bool ReferencesNonRootHomePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return false;

        if (HomePathRegex.IsMatch(command))
            return true;

        if (TildeUserRegex.IsMatch(command))
            return true;

        return false;
    }

    private static bool HasCronDataAvailable(ScanData data)
    {
        if (data.CronJobs.Count > 0)
            return true;

        return data.Capabilities.Any(c =>
            c.SourceName.Equals("/etc/crontab", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.d", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/var/spool/cron", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.daily", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.hourly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.weekly", StringComparison.OrdinalIgnoreCase) ||
            c.SourceName.StartsWith("/etc/cron.monthly", StringComparison.OrdinalIgnoreCase));
    }

    private static RuleResult NotApplicableResult()
    {
        return new RuleResult
        {
            RuleId = "CRON-003",
            Category = FindingCategories.CronJob,
            Passed = true,
            Status = RuleStatus.NotApplicable,
            ExplanationKey = "CRON-003",
            Description = "Root cron jobs should not reference non-root user directories — No cron data available (requires root or cron files not present).",
            CisMappings = new[]
            {
                new CisBenchmarkMapping
                {
                    ControlId = "CIS 6.2",
                    ControlName = "Configure System Account Security",
                    WhyItMatters = "System-wide cron jobs running as root should be system-wide. User-specific jobs should be placed in the user's own crontab. Root jobs referencing user directories may indicate privilege misuse or attacker persistence.",
                    BenchmarkReference = "CIS Ubuntu 24.04 LTS 6.2.1 — Ensure accounts in /etc/passwd use assigned UIDs"
                }
            },
            MitreTechniques = CronJobMitreMappings.Techniques
        };
    }
}
