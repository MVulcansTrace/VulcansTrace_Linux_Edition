using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Exports findings and their correlations as a Cytoscape.js-compatible JSON graph.
/// </summary>
public sealed class TraceMapJsonFormatter
{
    public string FileExtension => ".json";
    public string ContentType => "application/json";

    /// <summary>
    /// Produces a graph document with nodes (findings) and edges (correlations).
    /// </summary>
    public string Format(IReadOnlyList<Finding> findings, IReadOnlyList<CorrelationEdge> edges)
    {
        var nodes = findings.Select(f => new CytoscapeNode
        {
            Data = new NodeData
            {
                Id = f.Id.ToString("N"),
                Label = f.Category,
                Severity = f.Severity.ToString(),
                SourceHost = f.SourceHost,
                Target = f.Target,
                ShortDescription = f.ShortDescription,
                TimeRangeStart = f.TimeRangeStart,
                TimeRangeEnd = f.TimeRangeEnd
            }
        }).ToList();

        var cytoEdges = edges.Select(e => new CytoscapeEdge
        {
            Data = new EdgeData
            {
                Id = $"{e.FromFindingId:N}-{e.ToFindingId:N}",
                Source = e.FromFindingId.ToString("N"),
                Target = e.ToFindingId.ToString("N"),
                Type = e.CorrelationType.ToString(),
                Narrative = e.Narrative,
                Confidence = e.Confidence.ToString()
            }
        }).ToList();

        var document = new CytoscapeDocument
        {
            Elements = new CytoscapeElements
            {
                Nodes = nodes,
                Edges = cytoEdges
            }
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        return JsonSerializer.Serialize(document, options);
    }

    private sealed class CytoscapeDocument
    {
        public CytoscapeElements Elements { get; set; } = new();
    }

    private sealed class CytoscapeElements
    {
        public List<CytoscapeNode> Nodes { get; set; } = new();
        public List<CytoscapeEdge> Edges { get; set; } = new();
    }

    private sealed class CytoscapeNode
    {
        public NodeData Data { get; set; } = new();
    }

    private sealed class NodeData
    {
        public string Id { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string SourceHost { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string ShortDescription { get; set; } = string.Empty;
        public DateTime TimeRangeStart { get; set; }
        public DateTime TimeRangeEnd { get; set; }
    }

    private sealed class CytoscapeEdge
    {
        public EdgeData Data { get; set; } = new();
    }

    private sealed class EdgeData
    {
        public string Id { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Narrative { get; set; } = string.Empty;
        public string Confidence { get; set; } = string.Empty;
    }
}
