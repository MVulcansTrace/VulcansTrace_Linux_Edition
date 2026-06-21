using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;

/// <summary>
/// TI-003: Correlates file hashes against imported threat intel hash IOCs.
/// </summary>
public sealed class ThreatIntelHashRule : IRule
{
    private readonly IThreatIntelStore _store;

    public string Id => "TI-003";
    public string Category => "ThreatIntel";
    public string Description => "File hash matches a known malicious hash from threat intel";
    public string WhatItChecks => "Correlates file hashes against imported threat intel hash IOCs";
    public IReadOnlyList<string> SupportedDataSources => new[] { "file-hash" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        new MitreTechnique { TechniqueId = "T1204.002", TechniqueName = "User Execution: Malicious File", Tactic = "Execution", WhyItMatters = "A file with a known malicious hash is strong evidence of malware presence." }
    };

    public ThreatIntelHashRule(IThreatIntelStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public RuleResult Evaluate(ScanData data)
    {
        var hashIocs = _store.GetByType(IocType.FileHash).ToList();

        if (hashIocs.Count == 0 || data.FileHashes.Count == 0)
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        // Build a lookup: algorithm -> set of hash values
        var iocByAlgorithm = hashIocs
            .GroupBy(i => string.IsNullOrEmpty(i.Algorithm) ? "SHA-256" : i.Algorithm.ToUpperInvariant())
            .ToDictionary(
                g => g.Key,
                g => new HashSet<string>(g.Select(i => i.Value), StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);

        var matches = data.FileHashes
            .Where(f => iocByAlgorithm.TryGetValue(f.Algorithm.ToUpperInvariant(), out var set) && set.Contains(f.Hash))
            .ToList();

        if (matches.Count == 0)
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        var highestConfidence = 0;
        var variables = new Dictionary<string, string>();
        var index = 1;
        foreach (var match in matches.Take(10))
        {
            var ioc = hashIocs.First(i =>
                i.Value.Equals(match.Hash, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrEmpty(i.Algorithm) ? "SHA-256" : i.Algorithm).Equals(match.Algorithm, StringComparison.OrdinalIgnoreCase));
            highestConfidence = Math.Max(highestConfidence, ioc.ThreatScore);
            variables[$"match_{index}_path"] = match.Path;
            variables[$"match_{index}_hash"] = match.Hash;
            variables[$"match_{index}_algorithm"] = match.Algorithm;
            variables[$"match_{index}_confidence"] = ioc.ThreatScore.ToString();
            index++;
        }

        variables["count"] = matches.Count.ToString();
        variables["first_path"] = matches.First().Path;
        variables["first_hash"] = matches.First().Hash;

        var severity = highestConfidence switch
        {
            >= 80 => Severity.Critical,
            >= 60 => Severity.High,
            >= 40 => Severity.Medium,
            _ => Severity.Low
        };

        return RuleResult.Fail(Id, Category, Id, Description, severity,
            $"{matches.Count} file(s) match malicious hash(es)", variables, CisMappings, MitreTechniques);
    }
}
