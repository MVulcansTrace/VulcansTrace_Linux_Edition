using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules.ThreatIntel;

/// <summary>
/// TI-001: Correlates active network connections against imported threat intel IP IOCs.
/// </summary>
public sealed class ThreatIntelIpRule : IRule
{
    private readonly IThreatIntelStore _store;

    public string Id => "TI-001";
    public string Category => "ThreatIntel";
    public string Description => "Active connection to a known malicious IP address";
    public string WhatItChecks => "Correlates active connections against imported threat intel IP IOCs";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tunap", "threat-intel" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

    public IReadOnlyList<MitreTechnique> MitreTechniques => new[]
    {
        new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "Communication with known malicious IPs may indicate active C2 channels." }
    };

    public ThreatIntelIpRule(IThreatIntelStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public RuleResult Evaluate(ScanData data)
    {
        var ipIocs = _store.GetByType(IocType.IPv4)
            .Concat(_store.GetByType(IocType.IPv6))
            .ToList();

        if (ipIocs.Count == 0)
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        var ipSet = new HashSet<string>(ipIocs.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
        var matches = data.ActiveConnections
            .Where(c => ipSet.Contains(c.RemoteAddress))
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
            var ioc = ipIocs.First(i => i.Value.Equals(match.RemoteAddress, StringComparison.OrdinalIgnoreCase));
            highestConfidence = Math.Max(highestConfidence, ioc.Confidence);
            variables[$"match_{index}_ip"] = match.RemoteAddress;
            variables[$"match_{index}_port"] = match.RemotePort.ToString();
            variables[$"match_{index}_confidence"] = ioc.Confidence.ToString();
            index++;
        }

        variables["count"] = matches.Count.ToString();
        variables["first_ip"] = matches.First().RemoteAddress;
        variables["first_port"] = matches.First().RemotePort.ToString();

        var severity = highestConfidence switch
        {
            >= 80 => Severity.Critical,
            >= 60 => Severity.High,
            >= 40 => Severity.Medium,
            _ => Severity.Low
        };

        return RuleResult.Fail(Id, Category, Id, Description, severity,
            $"{matches.Count} connection(s) to malicious IP(s)", variables, CisMappings, MitreTechniques);
    }
}
