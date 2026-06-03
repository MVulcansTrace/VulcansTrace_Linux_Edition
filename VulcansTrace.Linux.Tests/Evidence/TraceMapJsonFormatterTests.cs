using System.Text.Json;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class TraceMapJsonFormatterTests
{
    private readonly TraceMapJsonFormatter _formatter = new();

    [Fact]
    public void Format_ContainsNodesAndEdges()
    {
        var baseTime = DateTime.UtcNow;
        var f1 = new Finding
        {
            Category = FindingCategories.Beaconing,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:443",
            TimeRangeStart = baseTime,
            TimeRangeEnd = baseTime.AddMinutes(5),
            ShortDescription = "Beaconing",
            Severity = Severity.Medium
        };
        var f2 = new Finding
        {
            Category = FindingCategories.LateralMovement,
            SourceHost = "192.168.1.100",
            Target = "internal",
            TimeRangeStart = baseTime.AddMinutes(10),
            TimeRangeEnd = baseTime.AddMinutes(15),
            ShortDescription = "Lateral",
            Severity = Severity.High
        };
        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "Escalation", CorrelationConfidence.High)
        };

        var json = _formatter.Format(new[] { f1, f2 }, edges);
        var doc = JsonDocument.Parse(json);
        var elements = doc.RootElement.GetProperty("elements");
        var nodes = elements.GetProperty("nodes");
        var edgeElements = elements.GetProperty("edges");

        Assert.Equal(2, nodes.GetArrayLength());
        Assert.Equal(1, edgeElements.GetArrayLength());

        var node0 = nodes[0];
        Assert.Equal(f1.Id.ToString("N"), node0.GetProperty("data").GetProperty("id").GetString());
        Assert.Equal("Beaconing", node0.GetProperty("data").GetProperty("label").GetString());

        var edge0 = edgeElements[0];
        Assert.Equal(f1.Id.ToString("N"), edge0.GetProperty("data").GetProperty("source").GetString());
        Assert.Equal(f2.Id.ToString("N"), edge0.GetProperty("data").GetProperty("target").GetString());
        Assert.Equal("EscalatesTo", edge0.GetProperty("data").GetProperty("type").GetString());
        Assert.Equal("Escalation", edge0.GetProperty("data").GetProperty("narrative").GetString());
    }

    [Fact]
    public void Format_NoEdges_StillProducesValidJson()
    {
        var json = _formatter.Format(Array.Empty<Finding>(), Array.Empty<CorrelationEdge>());
        var doc = JsonDocument.Parse(json);
        var elements = doc.RootElement.GetProperty("elements");

        Assert.Empty(elements.GetProperty("nodes").EnumerateArray());
        Assert.Empty(elements.GetProperty("edges").EnumerateArray());
    }

    [Fact]
    public void Format_EdgeIds_AreDeterministic()
    {
        var f1 = new Finding { Category = FindingCategories.Beaconing, SourceHost = "h1", ShortDescription = "A" };
        var f2 = new Finding { Category = FindingCategories.PortScan, SourceHost = "h1", ShortDescription = "B" };
        var f3 = new Finding { Category = FindingCategories.LateralMovement, SourceHost = "h1", ShortDescription = "C" };

        var edges = new List<CorrelationEdge>
        {
            new(f1.Id, f2.Id, CorrelationType.EscalatesTo, "e1", CorrelationConfidence.High),
            new(f2.Id, f3.Id, CorrelationType.TemporalSequence, "e2", CorrelationConfidence.Medium),
            new(f1.Id, f3.Id, CorrelationType.SameHost, "e3", CorrelationConfidence.Low)
        };

        var json = _formatter.Format(new[] { f1, f2, f3 }, edges);
        var doc = JsonDocument.Parse(json);
        var edgeElements = doc.RootElement.GetProperty("elements").GetProperty("edges");

        var ids = edgeElements.EnumerateArray()
            .Select(e => e.GetProperty("data").GetProperty("id").GetString())
            .ToList();

        // IDs must be derived from content, not list position
        Assert.Contains($"{f1.Id:N}-{f2.Id:N}", ids);
        Assert.Contains($"{f2.Id:N}-{f3.Id:N}", ids);
        Assert.Contains($"{f1.Id:N}-{f3.Id:N}", ids);
    }
}
