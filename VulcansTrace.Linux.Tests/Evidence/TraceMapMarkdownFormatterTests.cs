using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class TraceMapMarkdownFormatterTests
{
    private readonly TraceMapMarkdownFormatter _formatter = new();

    [Fact]
    public void ToMarkdown_NoEdges_ReturnsNoCorrelationsMessage()
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategories.PortScan,
                SourceHost = "10.0.0.1",
                ShortDescription = "Port scan",
                Severity = Severity.Medium
            }
        };

        var result = _formatter.ToMarkdown(findings, Array.Empty<CorrelationEdge>());

        Assert.Contains("No correlated attack chains", result);
        Assert.Contains("Port scan", result);
    }

    [Fact]
    public void ToMarkdown_WithEdge_ContainsNarrativeAndFindingDetails()
    {
        var baseTime = DateTime.UtcNow;
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing detected",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            Target = "internal hosts",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral movement",
            Severity = Severity.High
        };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Beaconing followed by lateral movement", CorrelationConfidence.High)
        };

        var result = _formatter.ToMarkdown(new[] { f1, f2 }, edges);

        Assert.Contains("# Incident Story — Trace Map", result);
        Assert.Contains("## Attack Chain 1", result);
        Assert.Contains("Beaconing detected", result);
        Assert.Contains("Lateral movement", result);
        Assert.Contains("Beaconing followed by lateral movement", result);
    }

    [Fact]
    public void ToMarkdown_WithCisMappings_IncludesControls()
    {
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            ShortDescription = "Beaconing",
            Severity = Severity.Medium,
            CisMappings = new[]
            {
                new CisBenchmarkMapping { ControlId = "CIS-12.1", ControlName = "Boundary Defense", WhyItMatters = "Important" }
            }
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            ShortDescription = "Lateral",
            Severity = Severity.High,
            CisMappings = new[]
            {
                new CisBenchmarkMapping { ControlId = "CIS-12.4", ControlName = "Network Segmentation", WhyItMatters = "Important" }
            }
        };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Escalation", CorrelationConfidence.High)
        };

        var result = _formatter.ToMarkdown(new[] { f1, f2 }, edges);

        Assert.Contains("CIS-12.4", result);
    }

    [Fact]
    public void ToMarkdown_NoEdges_ListsAllFindingsAsUnconnected()
    {
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            ShortDescription = "Beaconing",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.PortScan,
            SourceHost = "10.0.0.5",
            ShortDescription = "Port scan",
            Severity = Severity.Low
        };
        var edges = new List<CorrelationEdge>();

        var result = _formatter.ToMarkdown(new[] { f1, f2 }, edges);

        Assert.Contains("No correlated attack chains", result);
        Assert.Contains("Port scan", result);
    }

    [Fact]
    public void ToMarkdown_SomeUnconnected_SeparateSection()
    {
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            ShortDescription = "Beaconing",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            ShortDescription = "Lateral",
            Severity = Severity.High
        };
        var f3 = new Finding
        {
            Category = FindingCategories.PortScan,
            SourceHost = "10.0.0.5",
            ShortDescription = "Port scan",
            Severity = Severity.Low
        };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Escalation", CorrelationConfidence.High)
        };

        var result = _formatter.ToMarkdown(new[] { f1, f2, f3 }, edges);

        Assert.Contains("## Unconnected Findings", result);
        Assert.Contains("Port scan", result);
    }
}
