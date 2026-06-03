using System.Text;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Generates a human-readable incident story from correlated findings.
/// </summary>
public sealed class TraceMapMarkdownFormatter
{
    /// <summary>
    /// Produces a Markdown narrative of attack chains and unconnected findings.
    /// </summary>
    public string ToMarkdown(IReadOnlyList<Finding> findings, IReadOnlyList<CorrelationEdge> edges)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Incident Story — Trace Map");
        sb.AppendLine();

        if (edges.Count == 0)
        {
            sb.AppendLine("No correlated attack chains were detected in this audit.");
            sb.AppendLine();
            AppendUnconnectedFindings(sb, findings);
            return sb.ToString();
        }

        // Build attack chains from edges (deduplicated — first wins)
        var connectedFindingIds = edges.SelectMany(e => new[] { e.FromFindingId, e.ToFindingId }).ToHashSet();
        var findingById = findings.DistinctBy(f => f.Id).ToDictionary(f => f.Id);
        var edgeGroups = GroupEdgesIntoChains(edges, findingById);

        var chainNumber = 1;
        foreach (var chain in edgeGroups)
        {
            sb.AppendLine($"## Attack Chain {chainNumber}");
            sb.AppendLine();

            foreach (var edge in chain)
            {
                if (findingById.TryGetValue(edge.FromFindingId, out var from))
                {
                    sb.AppendLine($"- **{from.SourceHost}** — {from.ShortDescription} ({from.Category}, {from.Severity})");
                }

                sb.AppendLine($"  - *{edge.Narrative}*");

                if (findingById.TryGetValue(edge.ToFindingId, out var to))
                {
                    sb.AppendLine($"- **{to.SourceHost}** — {to.ShortDescription} ({to.Category}, {to.Severity})");
                    var cis = string.Join(", ", to.CisMappings.Select(c => c.ControlId).Distinct());
                    if (!string.IsNullOrEmpty(cis))
                    {
                        sb.AppendLine($"  - **CIS Controls:** {cis}");
                    }
                }

                sb.AppendLine();
            }

            chainNumber++;
        }

        // Unconnected findings
        var unconnected = findings.Where(f => !connectedFindingIds.Contains(f.Id)).ToList();
        if (unconnected.Count > 0)
        {
            sb.AppendLine("## Unconnected Findings");
            sb.AppendLine();
            foreach (var f in unconnected)
            {
                sb.AppendLine($"- **{f.SourceHost}** — {f.ShortDescription} ({f.Category}, {f.Severity})");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static List<List<CorrelationEdge>> GroupEdgesIntoChains(
        IReadOnlyList<CorrelationEdge> edges,
        IReadOnlyDictionary<Guid, Finding> findingById)
    {
        // Simple grouping: edges that share findings are part of the same chain
        var chains = new List<List<CorrelationEdge>>();
        var remaining = edges.ToList();

        while (remaining.Count > 0)
        {
            var chain = new List<CorrelationEdge> { remaining[0] };
            remaining.RemoveAt(0);

            bool added;
            do
            {
                added = false;
                var chainIds = chain.SelectMany(e => new[] { e.FromFindingId, e.ToFindingId }).ToHashSet();

                for (int i = remaining.Count - 1; i >= 0; i--)
                {
                    if (chainIds.Contains(remaining[i].FromFindingId) ||
                        chainIds.Contains(remaining[i].ToFindingId))
                    {
                        chain.Add(remaining[i]);
                        remaining.RemoveAt(i);
                        added = true;
                    }
                }
            } while (added);

            // Sort chain by time using finding start times
            chain.Sort((a, b) =>
            {
                var timeA = findingById.TryGetValue(a.FromFindingId, out var fa) ? fa.TimeRangeStart : DateTime.MinValue;
                var timeB = findingById.TryGetValue(b.FromFindingId, out var fb) ? fb.TimeRangeStart : DateTime.MinValue;
                return timeA.CompareTo(timeB);
            });

            chains.Add(chain);
        }

        return chains;
    }

    private static void AppendUnconnectedFindings(StringBuilder sb, IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            sb.AppendLine("No findings.");
            return;
        }

        foreach (var f in findings)
        {
            sb.AppendLine($"- **{f.SourceHost}** — {f.ShortDescription} ({f.Category}, {f.Severity})");
        }
    }
}
