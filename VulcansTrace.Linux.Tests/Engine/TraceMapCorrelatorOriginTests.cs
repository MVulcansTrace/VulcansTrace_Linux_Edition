using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Tests.Engine;

public class TraceMapCorrelatorOriginTests
{
    private readonly TraceMapCorrelator _correlator = new();

    [Fact]
    public void Correlate_DetectorFindingsWithEngineRuleIds_StillCreateTemporalSequenceEdges()
    {
        // Regression guard: engine findings carry ENG- rule ids but remain
        // FindingOrigin.Detector, so they must not be treated as posture findings.
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                RuleId = "ENG-BEACON-001",
                Category = FindingCategories.Beaconing,
                SourceHost = "10.0.0.1",
                Target = "target-a",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddMinutes(5),
                ShortDescription = "Beaconing"
            },
            new()
            {
                RuleId = "ENG-MACSPOOF-001",
                Category = FindingCategories.MacSpoofing,
                SourceHost = "10.0.0.1",
                Target = "target-b",
                TimeRangeStart = baseTime.AddMinutes(10),
                TimeRangeEnd = baseTime.AddMinutes(15),
                ShortDescription = "MAC spoof"
            },
            new()
            {
                RuleId = "ENG-PORTSCAN-001",
                Category = FindingCategories.PortScan,
                SourceHost = "10.0.0.1",
                Target = "target-c",
                TimeRangeStart = baseTime.AddMinutes(20),
                TimeRangeEnd = baseTime.AddMinutes(25),
                ShortDescription = "Port scan"
            }
        };

        var result = _correlator.Correlate(findings);

        var temporalEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.TemporalSequence).ToList();
        Assert.Equal(2, temporalEdges.Count);
    }

    [Fact]
    public void Correlate_MixedOrigins_SkipsTemporalSequenceOnlyForAgentRuleFindings()
    {
        var baseTime = DateTime.UtcNow;
        var detector = new Finding
        {
            RuleId = "ENG-BEACON-001",
            Category = FindingCategories.Beaconing,
            SourceHost = "10.0.0.1",
            Target = "target-a",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing"
        };
        var posture = new Finding
        {
            RuleId = "FW-001",
            Origin = FindingOrigin.AgentRule,
            Category = "Firewall",
            SourceHost = "10.0.0.1",
            Target = "firewall",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(10),
            ShortDescription = "Firewall inactive"
        };
        var detector2 = new Finding
        {
            RuleId = "ENG-PORTSCAN-001",
            Category = FindingCategories.PortScan,
            SourceHost = "10.0.0.1",
            Target = "target-c",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Port scan"
        };

        var result = _correlator.Correlate(new[] { detector, posture, detector2 });

        var temporalEdges = result.Edges.Where(e => e.CorrelationType == CorrelationType.TemporalSequence).ToList();
        // Consecutive pairs are detector→posture and posture→detector2; both involve the
        // posture finding, so neither may become a TemporalSequence edge.
        Assert.Empty(temporalEdges);
    }

    [Fact]
    public void Correlate_DetectorFindingsWithEngineRuleIds_StillFormCriticalChain()
    {
        var baseTime = DateTime.UtcNow;
        var beaconing = new Finding
        {
            RuleId = "ENG-BEACON-001",
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected"
        };
        var lateral = new Finding
        {
            RuleId = "ENG-LATMOVE-001",
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            Target = "multiple internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement detected"
        };
        var privEsc = new Finding
        {
            RuleId = "ENG-PRIVESC-001",
            Category = FindingCategories.PrivilegeEscalation,
            SourceHost = "192.168.1.100",
            Target = "admin ports in 5min window",
            TimeRangeStart = baseTime.AddMinutes(20),
            TimeRangeEnd = baseTime.AddMinutes(25),
            ShortDescription = "Privilege escalation indicator"
        };

        var result = _correlator.Correlate(new[] { beaconing, lateral, privEsc });

        Assert.Single(result.CriticalChains);
        Assert.Contains(result.Edges, e => e.CorrelationType == CorrelationType.EscalatesTo);
    }
}
