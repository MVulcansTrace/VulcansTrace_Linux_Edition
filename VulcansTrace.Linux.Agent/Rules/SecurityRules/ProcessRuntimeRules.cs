using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class ProcessRuntimeMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1055", TechniqueName = "Process Injection", Tactic = "Defense Evasion", WhyItMatters = "Runtime process anomalies indicate active injection, code execution, or post-exploitation activity." },
        new MitreTechnique { TechniqueId = "T1620", TechniqueName = "Reflective Code Loading", Tactic = "Defense Evasion", WhyItMatters = "RWX memory regions and deleted binaries are common artifacts of reflective loading and in-memory execution." },
        new MitreTechnique { TechniqueId = "T1574.006", TechniqueName = "Hijack Execution Flow: Dynamic Linker Hijacking", Tactic = "Persistence", WhyItMatters = "LD_PRELOAD manipulation forces legitimate processes to load attacker-controlled libraries." },
        new MitreTechnique { TechniqueId = "T1036", TechniqueName = "Masquerading", Tactic = "Defense Evasion", WhyItMatters = "Deleted binaries and orphaned processes are used to hide malware presence and evade detection." },
        new MitreTechnique { TechniqueId = "T1105", TechniqueName = "Ingress Tool Transfer", Tactic = "Command and Control", WhyItMatters = "Execution from temporary paths often indicates recently transferred tooling or payloads." },
        new MitreTechnique { TechniqueId = "T1059", TechniqueName = "Command and Scripting Interpreter", Tactic = "Execution", WhyItMatters = "Unexpected interpreters spawned by network services indicate remote code execution or webshell activity." },
    };
}

internal static class ProcessRuntimeRuleHelpers
{
    public static bool HasProcessDataAvailable(ScanData data)
    {
        if (data.ProcessRuntimes.Count > 0)
            return true;

        return data.Capabilities.Any(c =>
            c.SourceName.Equals("/proc", StringComparison.OrdinalIgnoreCase) &&
            c.Status is CapabilityStatus.Available or CapabilityStatus.PermissionLimited);
    }

    public static bool HasReadableMaps(ProcessRuntimeEntry proc) =>
        proc.MemoryMapsReadable || proc.MemoryMaps.Count > 0;

    public static bool HasReadableEnvironment(ProcessRuntimeEntry proc) =>
        proc.EnvironmentReadable || proc.Environment.Count > 0;

    public static bool HasReadableExe(ProcessRuntimeEntry proc) =>
        proc.ExePathReadable || !string.IsNullOrEmpty(proc.ExePath);

    public static bool HasRwxMap(ProcessRuntimeEntry proc) =>
        proc.MemoryMaps.Any(IsRwxMap);

    public static bool IsRwxMap(ProcessMemoryMap map) =>
        map.Permissions.Length >= 3 &&
        map.Permissions[0] == 'r' &&
        map.Permissions[1] == 'w' &&
        map.Permissions[2] == 'x';

    public static bool IsInterpreterProcess(ProcessRuntimeEntry proc) =>
        IsInterpreterName(proc.Name) ||
        IsInterpreterPath(proc.ExePath) ||
        IsInterpreterCommand(proc.Cmdline);

    public static bool IsInterpreterName(string name)
    {
        var lower = name.ToLowerInvariant();
        if (lower is "python" or "python3" or "perl" or "ruby" or "php")
            return true;

        if (lower.StartsWith("python", StringComparison.Ordinal) && lower.Length > 6 && char.IsDigit(lower[6]))
            return true;
        if (lower.StartsWith("php", StringComparison.Ordinal) && lower.Length > 3 && char.IsDigit(lower[3]))
            return true;
        if (lower.StartsWith("ruby", StringComparison.Ordinal) && lower.Length > 4 && char.IsDigit(lower[4]))
            return true;
        if (lower.StartsWith("perl", StringComparison.Ordinal) && lower.Length > 4 && char.IsDigit(lower[4]))
            return true;

        return false;
    }

    private static bool IsInterpreterPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var fileName = Path.GetFileName(path);
        return IsInterpreterName(fileName);
    }

    private static bool IsInterpreterCommand(string cmdline)
    {
        if (string.IsNullOrWhiteSpace(cmdline))
            return false;

        var firstToken = cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (string.IsNullOrWhiteSpace(firstToken))
            return false;

        return IsInterpreterPath(firstToken) || IsInterpreterName(firstToken);
    }

    public static void AddUnreadableCount(Dictionary<string, string> variables, string key, int count)
    {
        if (count > 0)
            variables[key] = count.ToString();
    }
}

/// <summary>
/// PROC-001: Detects processes with RWX (read-write-execute) memory mappings.
/// </summary>
public sealed class RwxMemoryRegionRule : IRule
{
    public string Id => "PROC-001";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Process has executable and writable memory regions (RWX)";
    public string WhatItChecks => "Inspects /proc/<pid>/maps for regions with rwxp permissions indicating potential code injection or shellcode";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/maps" };
    public Severity Severity => Severity.Critical;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1055"),
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1620")
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var readableProcesses = data.ProcessRuntimes
            .Where(ProcessRuntimeRuleHelpers.HasReadableMaps)
            .ToArray();
        if (readableProcesses.Length == 0)
            return NotApplicableResult("No readable /proc/<pid>/maps data available.");

        var violations = new List<ProcessRuntimeEntry>();
        foreach (var proc in readableProcesses)
        {
            if (ProcessRuntimeRuleHelpers.HasRwxMap(proc))
                violations.Add(proc);
        }

        bool anyMapsTruncated = data.ProcessRuntimes.Any(p => p.MapsTruncated);
        int mapsUnreadableCount = data.ProcessRuntimes.Count - readableProcesses.Length;

        if (violations.Count == 0)
        {
            var passMeta = new Dictionary<string, string>();
            if (anyMapsTruncated)
                passMeta["mapsTruncated"] = "true";
            ProcessRuntimeRuleHelpers.AddUnreadableCount(passMeta, "mapsUnreadableCount", mapsUnreadableCount);
            return RuleResult.Pass(Id, Category, Id, Description, variables: passMeta, cisMappings: CisMappings, mitreTechniques: MitreTechniques);
        }

        var first = violations[0];
        var target = $"{violations.Count} process{(violations.Count == 1 ? "" : "es")}: " +
            string.Join("; ", violations.Select(v => $"{v.Name}[{v.Pid}]"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        var failMeta = new Dictionary<string, string>
        {
            ["count"] = violations.Count.ToString(),
            ["firstPid"] = first.Pid.ToString(),
            ["firstName"] = first.Name,
            ["firstCmdline"] = first.Cmdline,
            ["allPids"] = allPids
        };
        if (anyMapsTruncated)
            failMeta["mapsTruncated"] = "true";
        ProcessRuntimeRuleHelpers.AddUnreadableCount(failMeta, "mapsUnreadableCount", mapsUnreadableCount);

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            failMeta, CisMappings, MitreTechniques);
    }

    private RuleResult NotApplicableResult(string? reason = null) =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — {reason ?? "No process runtime data available (requires /proc access)."}",
            CisMappings, MitreTechniques);
}

/// <summary>
/// PROC-002: Detects LD_PRELOAD or LD_AUDIT in process environments.
/// </summary>
public sealed class LdPreloadInjectionRule : IRule
{
    public string Id => "PROC-002";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Process environment contains LD_PRELOAD or LD_AUDIT";
    public string WhatItChecks => "Inspects /proc/<pid>/environ for dynamic linker hijacking variables";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/environ" };
    public Severity Severity => Severity.High;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1574.006")
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var readableProcesses = data.ProcessRuntimes
            .Where(ProcessRuntimeRuleHelpers.HasReadableEnvironment)
            .ToArray();
        if (readableProcesses.Length == 0)
            return NotApplicableResult("No readable /proc/<pid>/environ data available.");

        var violations = new List<(ProcessRuntimeEntry Proc, string Var)>();
        foreach (var proc in readableProcesses)
        {
            foreach (var env in proc.Environment)
            {
                if (env.StartsWith("LD_PRELOAD=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = env.AsSpan("LD_PRELOAD=".Length).Trim().ToString();
                    if (!string.IsNullOrEmpty(value))
                        violations.Add((proc, env));
                }
                else if (env.StartsWith("LD_AUDIT=", StringComparison.OrdinalIgnoreCase))
                {
                    var value = env.AsSpan("LD_AUDIT=".Length).Trim().ToString();
                    if (!string.IsNullOrEmpty(value))
                        violations.Add((proc, env));
                }
            }
        }

        bool anyEnvironTruncated = data.ProcessRuntimes.Any(p => p.EnvironTruncated);
        int environUnreadableCount = data.ProcessRuntimes.Count - readableProcesses.Length;

        if (violations.Count == 0)
        {
            var passMeta = new Dictionary<string, string>();
            if (anyEnvironTruncated)
                passMeta["environTruncated"] = "true";
            ProcessRuntimeRuleHelpers.AddUnreadableCount(passMeta, "environUnreadableCount", environUnreadableCount);
            return RuleResult.Pass(Id, Category, Id, Description, variables: passMeta, cisMappings: CisMappings, mitreTechniques: MitreTechniques);
        }

        var first = violations[0];
        var target = $"{violations.Count} process{(violations.Count == 1 ? "" : "es")}: " +
            string.Join("; ", violations.Select(v => $"{v.Proc.Name}[{v.Proc.Pid}] ({v.Var})"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Proc.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        var failMeta = new Dictionary<string, string>
        {
            ["count"] = violations.Count.ToString(),
            ["firstPid"] = first.Proc.Pid.ToString(),
            ["firstName"] = first.Proc.Name,
            ["firstVariable"] = first.Var,
            ["allPids"] = allPids
        };
        if (anyEnvironTruncated)
            failMeta["environTruncated"] = "true";
        ProcessRuntimeRuleHelpers.AddUnreadableCount(failMeta, "environUnreadableCount", environUnreadableCount);

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            failMeta, CisMappings, MitreTechniques);
    }

    private RuleResult NotApplicableResult(string? reason = null) =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — {reason ?? "No process runtime data available (requires /proc access)."}",
            CisMappings, MitreTechniques);
}

/// <summary>
/// PROC-003: Detects processes executing deleted binaries or running from temporary paths.
/// </summary>
public sealed class DeletedBinaryExecutionRule : IRule
{
    public string Id => "PROC-003";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Process is executing a deleted binary or from a temporary path";
    public string WhatItChecks => "Inspects /proc/<pid>/exe for (deleted) suffix or execution from /tmp, /dev/shm, /var/tmp";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/exe" };
    public Severity Severity => Severity.High;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1036"),
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1105")
    };

    private static readonly string[] TempPathPrefixes =
    {
        "/tmp/", "/var/tmp/", "/dev/shm/"
    };

    private static readonly string[] TempPathExactMatches =
    {
        "/tmp", "/var/tmp", "/dev/shm"
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var readableProcesses = data.ProcessRuntimes
            .Where(ProcessRuntimeRuleHelpers.HasReadableExe)
            .ToArray();
        if (readableProcesses.Length == 0)
            return NotApplicableResult("No readable /proc/<pid>/exe data available.");

        var violations = new List<ProcessRuntimeEntry>();
        foreach (var proc in readableProcesses)
        {
            var exe = proc.ExePath;
            if (string.IsNullOrEmpty(exe))
                continue;

            if (exe.EndsWith(" (deleted)", StringComparison.Ordinal))
            {
                violations.Add(proc);
                continue;
            }

            foreach (var prefix in TempPathPrefixes)
            {
                if (exe.StartsWith(prefix, StringComparison.Ordinal))
                {
                    violations.Add(proc);
                    break;
                }
            }

            foreach (var exact in TempPathExactMatches)
            {
                if (exe.Equals(exact, StringComparison.Ordinal))
                {
                    violations.Add(proc);
                    break;
                }
            }
        }

        int exeUnreadableCount = data.ProcessRuntimes.Count - readableProcesses.Length;

        if (violations.Count == 0)
        {
            var passMeta = new Dictionary<string, string>();
            ProcessRuntimeRuleHelpers.AddUnreadableCount(passMeta, "exeUnreadableCount", exeUnreadableCount);
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques, passMeta);
        }

        var first = violations[0];
        var target = $"{violations.Count} process{(violations.Count == 1 ? "" : "es")}: " +
            string.Join("; ", violations.Select(v => $"{v.Name}[{v.Pid}] -> {v.ExePath}"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        var failMeta = new Dictionary<string, string>
        {
            ["count"] = violations.Count.ToString(),
            ["firstPid"] = first.Pid.ToString(),
            ["firstName"] = first.Name,
            ["firstExePath"] = first.ExePath,
            ["allPids"] = allPids
        };
        ProcessRuntimeRuleHelpers.AddUnreadableCount(failMeta, "exeUnreadableCount", exeUnreadableCount);

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            failMeta, CisMappings, MitreTechniques);
    }

    private RuleResult NotApplicableResult(string? reason = null) =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — {reason ?? "No process runtime data available (requires /proc access)."}",
            CisMappings, MitreTechniques);
}

/// <summary>
/// PROC-004: Detects orphaned processes with anomalous names running under init.
/// </summary>
public sealed class OrphanedAnomalousProcessRule : IRule
{
    public string Id => "PROC-004";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Orphaned process with anomalous name running under init";
    public string WhatItChecks => "Detects processes with PPid=1 whose names appear randomly generated (high length, alphanumeric, multiple digits)";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/status", "/proc/<pid>/comm" };
    public Severity Severity => Severity.Medium;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1036")
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var violations = new List<ProcessRuntimeEntry>();
        foreach (var proc in data.ProcessRuntimes)
        {
            if (proc.Ppid != 1)
                continue;

            if (IsAnomalousName(proc.Name))
                violations.Add(proc);
        }

        if (violations.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = violations[0];
        var target = $"{violations.Count} process{(violations.Count == 1 ? "" : "es")}: " +
            string.Join("; ", violations.Select(v => $"{v.Name}[{v.Pid}]"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string>
            {
                ["count"] = violations.Count.ToString(),
                ["firstPid"] = first.Pid.ToString(),
                ["firstName"] = first.Name,
                ["firstCmdline"] = first.Cmdline,
                ["allPids"] = allPids
            }, CisMappings, MitreTechniques);
    }

    internal static bool IsAnomalousName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length < 10)
            return false;

        // Must be entirely alphanumeric
        if (!name.All(char.IsLetterOrDigit))
            return false;

        // Must contain at least 3 digits (random malware names are often alphanumeric with digits)
        int digitCount = name.Count(char.IsDigit);
        if (digitCount < 3)
            return false;

        return true;
    }

    private RuleResult NotApplicableResult() =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — No process runtime data available (requires /proc access).",
            CisMappings, MitreTechniques);
}

/// <summary>
/// PROC-005: Detects suspicious parent-child process relationships.
/// </summary>
public sealed class SuspiciousParentChildRule : IRule
{
    public string Id => "PROC-005";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Suspicious parent-child process relationship detected";
    public string WhatItChecks => "Detects unexpected interpreter or shell processes spawned by network services, databases, or cron";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/status", "/proc/<pid>/comm" };
    public Severity Severity => Severity.High;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1059")
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var pidToName = data.ProcessRuntimes
            .GroupBy(p => p.Pid)
            .ToDictionary(g => g.Key, g => g.First().Name);
        var violations = new List<(ProcessRuntimeEntry Child, string ParentName)>();
        int missingParentCount = 0;
        int totalChecked = 0;

        foreach (var proc in data.ProcessRuntimes)
        {
            if (proc.Ppid <= 0)
                continue;

            totalChecked++;

            if (!pidToName.TryGetValue(proc.Ppid, out var parentName))
            {
                missingParentCount++;
                continue;
            }

            if (IsSuspiciousPair(parentName, proc.Name))
                violations.Add((Child: proc, ParentName: parentName));
        }

        if (violations.Count == 0)
        {
            var passMeta = new Dictionary<string, string>
            {
                ["missingParentCount"] = missingParentCount.ToString(),
                ["totalChecked"] = totalChecked.ToString()
            };
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques, passMeta);
        }

        var first = violations[0];
        var target = $"{violations.Count} suspicious relationship{(violations.Count == 1 ? "" : "s")}: " +
            string.Join("; ", violations.Select(v => $"{v.ParentName}[{v.Child.Ppid}] -> {v.Child.Name}[{v.Child.Pid}]"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Child.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string>
            {
                ["count"] = violations.Count.ToString(),
                ["firstChildPid"] = first.Child.Pid.ToString(),
                ["firstChildName"] = first.Child.Name,
                ["firstParentName"] = first.ParentName,
                ["allPids"] = allPids,
                ["missingParentCount"] = missingParentCount.ToString(),
                ["totalChecked"] = totalChecked.ToString()
            }, CisMappings, MitreTechniques);
    }

    internal static bool IsSuspiciousPair(string parentName, string childName)
    {
        var parentLower = parentName.ToLowerInvariant();
        var childLower = childName.ToLowerInvariant();

        // Web servers spawning shells or interpreters
        if (parentLower is "apache2" or "nginx" || parentLower.StartsWith("httpd", StringComparison.Ordinal))
        {
            if (IsInterpreter(childLower))
                return true;
        }

        // SSH spawning non-shell interpreters (bash/sh are normal login shells; interpreters are not)
        if (parentLower == "sshd")
        {
            if (IsInterpreter(childLower) && childLower is not "bash" and not "sh" and not "dash" and not "zsh")
                return true;
        }

        // Databases spawning shells or interpreters
        if (parentLower is "mysqld" or "mongod" or "redis-server" || parentLower.StartsWith("postgres", StringComparison.Ordinal))
        {
            if (IsInterpreter(childLower))
                return true;
        }

        // Cron spawning network tools or interpreters
        if (parentLower is "cron" or "crond")
        {
            if (IsInterpreter(childLower) || childLower is "curl" or "wget" or "nc" or "ncat")
                return true;
        }

        return false;
    }

    private static bool IsInterpreter(string name) =>
        name is "bash" or "sh" or "dash" or "zsh" ||
        ProcessRuntimeRuleHelpers.IsInterpreterName(name);

    private RuleResult NotApplicableResult() =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — No process runtime data available (requires /proc access).",
            CisMappings, MitreTechniques);
}

/// <summary>
/// PROC-006: Detects interpreter processes with RWX memory mappings.
/// </summary>
public sealed class InterpreterRwxMemoryRule : IRule
{
    public string Id => "PROC-006";
    public string Category => FindingCategories.ProcessRuntime;
    public string Description => "Interpreter process has executable and writable memory regions (RWX)";
    public string WhatItChecks => "Inspects python, perl, ruby, and php processes for RWX mappings that may indicate in-memory payload execution";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/<pid>/comm", "/proc/<pid>/cmdline", "/proc/<pid>/exe", "/proc/<pid>/maps" };
    public Severity Severity => Severity.Critical;
    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1055"),
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1620"),
        ProcessRuntimeMitreMappings.Techniques.First(t => t.TechniqueId == "T1059")
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (!ProcessRuntimeRuleHelpers.HasProcessDataAvailable(data))
            return NotApplicableResult();

        var readableProcesses = data.ProcessRuntimes
            .Where(ProcessRuntimeRuleHelpers.HasReadableMaps)
            .ToArray();
        if (readableProcesses.Length == 0)
            return NotApplicableResult("No readable /proc/<pid>/maps data available.");

        var violations = readableProcesses
            .Where(p => ProcessRuntimeRuleHelpers.IsInterpreterProcess(p) && ProcessRuntimeRuleHelpers.HasRwxMap(p))
            .ToArray();

        bool anyMapsTruncated = data.ProcessRuntimes.Any(p => p.MapsTruncated);
        int mapsUnreadableCount = data.ProcessRuntimes.Count - readableProcesses.Length;

        if (violations.Length == 0)
        {
            var passMeta = new Dictionary<string, string>();
            if (anyMapsTruncated)
                passMeta["mapsTruncated"] = "true";
            ProcessRuntimeRuleHelpers.AddUnreadableCount(passMeta, "mapsUnreadableCount", mapsUnreadableCount);
            return RuleResult.Pass(Id, Category, Id, Description, variables: passMeta, cisMappings: CisMappings, mitreTechniques: MitreTechniques);
        }

        var first = violations[0];
        var target = $"{violations.Length} interpreter process{(violations.Length == 1 ? "" : "es")}: " +
            string.Join("; ", violations.Select(v => $"{v.Name}[{v.Pid}]"));

        if (target.Length > 500)
            target = target[..500] + "...";

        var allPids = string.Join(",", violations.Select(v => v.Pid));
        if (allPids.Length > 500)
            allPids = allPids[..497] + "...";

        var firstRwxMap = first.MemoryMaps.FirstOrDefault(ProcessRuntimeRuleHelpers.IsRwxMap);
        var failMeta = new Dictionary<string, string>
        {
            ["count"] = violations.Length.ToString(),
            ["firstPid"] = first.Pid.ToString(),
            ["firstName"] = first.Name,
            ["firstCmdline"] = first.Cmdline,
            ["firstMapPath"] = firstRwxMap?.Path ?? string.Empty,
            ["allPids"] = allPids
        };
        if (anyMapsTruncated)
            failMeta["mapsTruncated"] = "true";
        ProcessRuntimeRuleHelpers.AddUnreadableCount(failMeta, "mapsUnreadableCount", mapsUnreadableCount);

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            failMeta, CisMappings, MitreTechniques);
    }

    private RuleResult NotApplicableResult(string? reason = null) =>
        RuleResult.NotApplicable(Id, Category, Id,
            $"{Description} — {reason ?? "No process runtime data available (requires /proc access)."}",
            CisMappings, MitreTechniques);
}
