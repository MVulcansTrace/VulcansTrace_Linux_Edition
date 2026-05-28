using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Tests.Engine;

public class RiskEscalatorTests
{
    private readonly RiskEscalator _escalator = new();

    [Fact]
    public void Escalate_BeaconingAndLateralMovement_SameSource_EscalatesToCritical()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Beaconing detected",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Lateral movement detected",
                Details = "Contacted 5 internal hosts"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_FlagAnomalyAndPortScan_SameSource_EscalatesToCritical()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.FlagAnomaly,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "192.168.1.1:22",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow,
                ShortDescription = "FIN without SYN",
                Details = "Stealth scan"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "multiple hosts/ports",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(2),
                ShortDescription = "Port scan detected",
                Details = "20 distinct destinations"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_MacSpoofingAndInterfaceHopping_SameSource_EscalatesToCritical()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.MacSpoofing,
                Severity = Severity.High,
                SourceHost = "192.168.1.50",
                Target = "multiple MAC addresses",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(10),
                ShortDescription = "MAC spoofing",
                Details = "3 MACs for same IP"
            },
            new()
            {
                Category = FindingCategories.InterfaceHopping,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.50",
                Target = "3 network interfaces",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(10),
                ShortDescription = "Interface hopping",
                Details = "Switched between eth0, eth1, wlan0"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_DifferentSources_NoEscalation()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Beaconing from host A",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.200",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Lateral movement from host B",
                Details = "Different source"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.Equal(Severity.Medium, result[0].Severity);
        Assert.Equal(Severity.High, result[1].Severity);
    }

    [Fact]
    public void Escalate_EmptyFindings_ReturnsEmpty()
    {
        var result = _escalator.Escalate(Array.Empty<Finding>());

        Assert.Empty(result);
    }

    [Fact]
    public void Escalate_AlreadyCritical_NotModified()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Critical,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Already critical beaconing",
                Details = "Already escalated"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Lateral movement",
                Details = "Needs escalation"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_NonOverlappingTimeRanges_AfterB_CalculatesGapCorrectly()
    {
        // Regression test for the bug where GetTimeGapHours returned
        // (a.End - b.Start) instead of (a.Start - b.End) when a was after b.
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.FlagAnomaly,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "192.168.1.1:22",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddHours(1),
                ShortDescription = "FIN without SYN",
                Details = "Stealth scan"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                Severity = Severity.Medium,
                SourceHost = "10.0.0.99",
                Target = "multiple hosts/ports",
                TimeRangeStart = baseTime.AddHours(3),
                TimeRangeEnd = baseTime.AddHours(4),
                ShortDescription = "Port scan detected",
                Details = "20 distinct destinations"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        // Gap is 2 hours (3h - 1h), well within 24h threshold, so both escalate
        Assert.All(result, f => Assert.Equal(Severity.Critical, f.Severity));
    }

    [Fact]
    public void Escalate_NonOverlappingTimeRanges_GapExceeds24h_NoEscalation()
    {
        var baseTime = DateTime.UtcNow;
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = baseTime,
                TimeRangeEnd = baseTime.AddHours(1),
                ShortDescription = "Beaconing detected",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = baseTime.AddHours(26),
                TimeRangeEnd = baseTime.AddHours(27),
                ShortDescription = "Lateral movement detected",
                Details = "Contacted 5 internal hosts"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(2, result.Count);
        Assert.Equal(Severity.Medium, result[0].Severity);
        Assert.Equal(Severity.High, result[1].Severity);
    }

    [Fact]
    public void Escalate_UnrelatedFinding_NotEscalated()
    {
        // Beaconing + LateralMovement from same host triggers correlation,
        // but an unrelated PortScan finding should NOT be escalated.
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.Beaconing,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "10.0.0.5:443",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Beaconing detected",
                Details = "Regular intervals"
            },
            new()
            {
                Category = FindingCategories.LateralMovement,
                Severity = Severity.High,
                SourceHost = "192.168.1.100",
                Target = "multiple internal hosts",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(5),
                ShortDescription = "Lateral movement detected",
                Details = "Contacted 5 internal hosts"
            },
            new()
            {
                Category = FindingCategories.PortScan,
                Severity = Severity.Medium,
                SourceHost = "192.168.1.100",
                Target = "multiple hosts/ports",
                TimeRangeStart = DateTime.UtcNow,
                TimeRangeEnd = DateTime.UtcNow.AddMinutes(2),
                ShortDescription = "Port scan detected",
                Details = "20 distinct destinations"
            }
        };

        var result = _escalator.Escalate(findings);

        Assert.Equal(3, result.Count);

        // Beaconing and LateralMovement should be escalated to Critical
        var beaconing = result.Single(f => f.Category == FindingCategories.Beaconing);
        Assert.Equal(Severity.Critical, beaconing.Severity);

        var lateral = result.Single(f => f.Category == FindingCategories.LateralMovement);
        Assert.Equal(Severity.Critical, lateral.Severity);

        // PortScan is unrelated to the Beaconing+LateralMovement correlation pair
        var portScan = result.Single(f => f.Category == FindingCategories.PortScan);
        Assert.Equal(Severity.Medium, portScan.Severity);
    }
}
