using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;

/// <summary>
/// TI-002: Correlates open listening ports against imported threat intel port IOCs.
/// </summary>
public sealed class ThreatIntelPortRule : IRule
{
    private readonly IThreatIntelStore _store;

    public string Id => "TI-002";
    public string Category => "ThreatIntel";
    public string Description => "Open port matches a known malicious port from threat intel";
    public string WhatItChecks => "Correlates open listening ports against imported threat intel port IOCs";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "threat-intel" };
    // Reads OpenPorts (produced by the Port scanner); declare it so Port runs for /threatintel audits.
    public IReadOnlyCollection<string> RequiredDataFields => new[] { "OpenPorts" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        new MitreTechnique { TechniqueId = "T1571", TechniqueName = "Non-Standard Port", Tactic = "Command and Control", WhyItMatters = "Listening on known malicious ports may indicate non-standard C2 or backdoor services." }
    };

    public ThreatIntelPortRule(IThreatIntelStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public RuleResult Evaluate(ScanData data)
    {
        var portIocs = _store.GetByType(IocType.Port).ToList();

        if (portIocs.Count == 0)
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        var portMap = portIocs
            .Where(i => int.TryParse(i.Value, out _))
            .ToDictionary(i => int.Parse(i.Value), i => i);

        var matches = data.OpenPorts
            .Where(p => portMap.ContainsKey(p.LocalPort))
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
            var ioc = portMap[match.LocalPort];
            highestConfidence = Math.Max(highestConfidence, ioc.ThreatScore);
            variables[$"match_{index}_port"] = match.LocalPort.ToString();
            variables[$"match_{index}_address"] = match.LocalAddress;
            variables[$"match_{index}_process"] = match.ProcessName ?? "unknown";
            variables[$"match_{index}_confidence"] = ioc.ThreatScore.ToString();
            index++;
        }

        variables["count"] = matches.Count.ToString();
        variables["first_port"] = matches.First().LocalPort.ToString();
        variables["first_process"] = matches.First().ProcessName ?? "unknown";

        var severity = highestConfidence switch
        {
            >= 80 => Severity.Critical,
            >= 60 => Severity.High,
            >= 40 => Severity.Medium,
            _ => Severity.Low
        };

        return RuleResult.Fail(Id, Category, Id, Description, severity,
            $"{matches.Count} open port(s) match malicious IOC(s)", variables, CisMappings, MitreTechniques);
    }
}
