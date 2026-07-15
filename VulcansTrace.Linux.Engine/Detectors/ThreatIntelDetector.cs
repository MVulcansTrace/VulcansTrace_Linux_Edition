using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Correlates firewall log events against imported threat intelligence IOCs.
/// Flags matches on source IPs, destination IPs, and destination ports.
/// </summary>
public sealed class ThreatIntelDetector : IDetector
{
    private static readonly IReadOnlyList<MitreTechnique> s_mitreTechniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "Communication with known-bad IPs or ports may indicate active C2." },
        new MitreTechnique { TechniqueId = "T1571", TechniqueName = "Non-Standard Port", Tactic = "Command and Control", WhyItMatters = "Known malicious ports in traffic may indicate non-standard C2 channels." }
    };

    private readonly IThreatIntelStore _store;

    public IReadOnlyList<MitreTechnique> MitreTechniques => s_mitreTechniques;

    /// <summary>
    /// Initializes a new instance of the <see cref="ThreatIntelDetector"/> class.
    /// </summary>
    /// <param name="store">The threat intel store containing imported IOCs.</param>
    public ThreatIntelDetector(IThreatIntelStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (_store.Count == 0 || events.Count == 0)
        {
            return DetectionResult.Empty;
        }

        var ipIocs = _store.GetByType(IocType.IPv4)
            .Concat(_store.GetByType(IocType.IPv6))
            .ToList();
        var portIocs = _store.GetByType(IocType.Port).ToList();

        if (ipIocs.Count == 0 && portIocs.Count == 0)
        {
            return DetectionResult.Empty;
        }

        var ipSet = new HashSet<string>(ipIocs.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
        var portSet = new HashSet<int>(portIocs.Select(i => int.TryParse(i.Value, out var p) ? p : -1).Where(p => p > 0));
        var portMap = portIocs
            .Where(i => int.TryParse(i.Value, out _))
            .ToDictionary(i => int.Parse(i.Value), i => i);

        var findings = new List<Finding>();
        var warnings = new List<string>();
        var processedKeys = new HashSet<string>();

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // IP match on source or destination
            if (ipSet.Contains(evt.SourceIP))
            {
                var ioc = ipIocs.First(i => i.Value.Equals(evt.SourceIP, StringComparison.OrdinalIgnoreCase));
                var key = $"{evt.SourceIP}|src";
                if (processedKeys.Add(key))
                {
                    findings.Add(CreateFinding(ioc, "source IP", evt.SourceIP, evt));
                }
            }

            if (ipSet.Contains(evt.DestinationIP))
            {
                var ioc = ipIocs.First(i => i.Value.Equals(evt.DestinationIP, StringComparison.OrdinalIgnoreCase));
                var key = $"{evt.DestinationIP}|dst";
                if (processedKeys.Add(key))
                {
                    findings.Add(CreateFinding(ioc, "destination IP", evt.DestinationIP, evt));
                }
            }

            // Port match on destination port
            if (portSet.Contains(evt.DestinationPort) && portMap.TryGetValue(evt.DestinationPort, out var portIoc))
            {
                var key = $"port:{evt.DestinationPort}";
                if (processedKeys.Add(key))
                {
                    findings.Add(CreateFinding(portIoc, "destination port", evt.DestinationPort.ToString(), evt));
                }
            }
        }

        return new DetectionResult(findings, warnings);
    }

    private static Finding CreateFinding(IocEntry ioc, string matchType, string observedValue, UnifiedEvent evt)
    {
        var severity = ioc.ThreatScore switch
        {
            >= 80 => Severity.Critical,
            >= 60 => Severity.High,
            >= 40 => Severity.Medium,
            _ => Severity.Low
        };

        var description = string.IsNullOrWhiteSpace(ioc.Description)
            ? $"Imported from {ioc.Source}."
            : ioc.Description;

        var signals = new List<EvidenceSignal>
        {
            new EvidenceSignal
            {
                Name = $"IOC match on {matchType}",
                Source = EvidenceSignal.ThreatIntelSource,
                Explanation = $"Matched {observedValue} against imported IOC from {ioc.Source} (threat score: {ioc.ThreatScore}%)"
            }
        };

        return new Finding
        {
            RuleId = EngineRuleIds.ThreatIntel,
            Category = FindingCategories.ThreatIntel,
            Severity = severity,
            Confidence = FindingConfidenceCalculator.Calculate(signals),
            SourceHost = evt.SourceIP,
            Target = $"{evt.DestinationIP}:{evt.DestinationPort}",
            TimeRangeStart = evt.Timestamp,
            TimeRangeEnd = evt.Timestamp,
            ShortDescription = $"Threat intel match: {matchType} {observedValue} (threat score: {ioc.ThreatScore}%)",
            Details = $"Observed in firewall log ({evt.Protocol}/{evt.Action}). Matched against imported IOC from {ioc.Source}. {description}",
            MitreTechniques = s_mitreTechniques,
            EvidenceSignals = signals
        };
    }
}
