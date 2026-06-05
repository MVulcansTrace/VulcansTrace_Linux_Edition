using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class YaraMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique
        {
            TechniqueId = "T1204.002",
            TechniqueName = "User Execution: Malicious File",
            Tactic = "Execution",
            WhyItMatters = "A YARA rule match indicates the file contains patterns associated with known malicious or suspicious tooling."
        },
        new MitreTechnique
        {
            TechniqueId = "T1027",
            TechniqueName = "Obfuscated Files or Information",
            Tactic = "Defense Evasion",
            WhyItMatters = "Attackers frequently pack, encrypt, or otherwise obfuscate binaries to evade static detection."
        }
    };
}

/// <summary>
/// YARA-001: Suspicious or malicious binaries and scripts detected by YARA rule matches.
/// </summary>
public sealed class YaraMatchRule : IRule
{
    public string Id => "YARA-001";
    public string Category => FindingCategories.Yara;
    public string Description => "Suspicious or malicious binaries and scripts detected by YARA";
    public string WhatItChecks => "Scans SUID/SGID binaries, running process executables, and cron scripts against bundled and custom YARA rules";
    public IReadOnlyList<string> SupportedDataSources => new[] { "yara-scan" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 10.1",
            ControlName = "Ensure malicious software is detected and prevented",
            WhyItMatters = "Static signature scanning complements behavioral detection by catching known-bad patterns in binaries and scripts before they execute.",
            BenchmarkReference = "CIS Controls v8 10.1 — Deploy and Maintain Anti-Malware Software"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => YaraMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var entries = data.YaraMatches
            .OrderBy(e => e.TargetPath, StringComparer.Ordinal)
            .ThenBy(e => e.RuleIdentifier, StringComparer.Ordinal)
            .ToList();

        if (entries.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var first = entries.First();
        var firstDisplayPath = GetDisplayPath(first);
        var matchList = string.Join("\n", entries.Select((entry, index) =>
            $"{index + 1}. {GetDisplayPath(entry)} (scan path: {entry.TargetPath}, kind: {entry.TargetKind}, rule: {entry.RuleIdentifier}, pid: {entry.ProcessId?.ToString() ?? "n/a"})"));

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            firstDisplayPath,
            new Dictionary<string, string>
            {
                ["count"] = entries.Count.ToString(),
                ["path"] = firstDisplayPath,
                ["scanPath"] = first.TargetPath,
                ["resolvedPath"] = string.IsNullOrWhiteSpace(first.ResolvedTargetPath) ? first.TargetPath : first.ResolvedTargetPath,
                ["targetKind"] = first.TargetKind,
                ["ruleIdentifier"] = first.RuleIdentifier,
                ["processId"] = first.ProcessId?.ToString() ?? "n/a",
                ["matchDescription"] = string.IsNullOrWhiteSpace(first.MatchDescription) ? "n/a" : first.MatchDescription,
                ["matchList"] = matchList
            }, CisMappings, MitreTechniques);
    }

    private static string GetDisplayPath(YaraMatchEntry entry)
    {
        return string.IsNullOrWhiteSpace(entry.ResolvedTargetPath) ? entry.TargetPath : entry.ResolvedTargetPath;
    }
}
