using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Discovers directed correlation edges between findings based on host grouping,
/// time proximity, and known attack-chain pairs.
/// </summary>
/// <remarks>
/// This class does NOT mutate findings. It returns the original findings unchanged
/// alongside the edges that connect them.
/// </remarks>
public sealed class TraceMapCorrelator
{
    private const double MaxGapHours = 24.0;

    /// <summary>
    /// Analyzes findings and produces correlation edges where attack-chain patterns are detected.
    /// </summary>
    public TraceMapResult Correlate(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return new TraceMapResult { Findings = findings, Edges = Array.Empty<CorrelationEdge>() };
        }

        var edges = new List<CorrelationEdge>();
        var byHost = findings.GroupBy(f => f.SourceHost, StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var group in byHost)
        {
            var groupFindings = group.ToList();
            var categories = groupFindings.Select(f => f.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Pair 1: Beaconing + LateralMovement
            if (categories.Contains(FindingCategories.Beaconing) && categories.Contains(FindingCategories.LateralMovement))
            {
                edges.AddRange(FindEdgesForPair(
                    groupFindings,
                    FindingCategories.Beaconing,
                    FindingCategories.LateralMovement,
                    CorrelationType.EscalatesTo));
            }

            // Pair 2: FlagAnomaly + PortScan
            if (categories.Contains(FindingCategories.FlagAnomaly) && categories.Contains(FindingCategories.PortScan))
            {
                edges.AddRange(FindEdgesForPair(
                    groupFindings,
                    FindingCategories.FlagAnomaly,
                    FindingCategories.PortScan,
                    CorrelationType.EscalatesTo));
            }

            // Pair 3: MacSpoofing + InterfaceHopping
            if (categories.Contains(FindingCategories.MacSpoofing) && categories.Contains(FindingCategories.InterfaceHopping))
            {
                edges.AddRange(FindEdgesForPair(
                    groupFindings,
                    FindingCategories.MacSpoofing,
                    FindingCategories.InterfaceHopping,
                    CorrelationType.EscalatesTo));
            }
        }

        // Detect critical triple chains
        var criticalChains = new List<CriticalChain>();
        foreach (var group in byHost)
        {
            var groupFindings = group.ToList();
            var categories = groupFindings.Select(f => f.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

            if ((categories.Contains(FindingCategories.Beaconing) || categories.Contains(FindingCategories.C2Channel)) &&
                categories.Contains(FindingCategories.LateralMovement) &&
                categories.Contains(FindingCategories.PrivilegeEscalation))
            {
                // The opening stage is either a beacon or a C2 channel — whichever established the
                // attacker's presence on this host — so the slot may hold either category.
                var foothold = groupFindings
                    .Where(f => IsCategory(f, FindingCategories.Beaconing) || IsCategory(f, FindingCategories.C2Channel))
                    .OrderBy(f => f.TimeRangeStart)
                    .First();
                var lateral = groupFindings.Where(f => IsCategory(f, FindingCategories.LateralMovement)).OrderBy(f => f.TimeRangeStart).First();
                var privEsc = groupFindings.Where(f => IsCategory(f, FindingCategories.PrivilegeEscalation)).OrderBy(f => f.TimeRangeStart).First();
                var ordered = new[] { foothold, lateral, privEsc }.OrderBy(f => f.TimeRangeStart).ToList();

                criticalChains.Add(new CriticalChain
                {
                    Host = group.Key,
                    Narrative = $"Critical chain detected on {group.Key}: Beaconing/C2 → LateralMovement → PrivilegeEscalation.",
                    FindingIds = ordered.Select(f => f.Id).ToList()
                });
            }
        }

        // Track which finding pairs are already connected so we don't add weaker duplicates
        var connectedPairs = edges
            .Select(e => (e.FromFindingId, e.ToFindingId))
            .ToHashSet();

        foreach (var group in byHost)
        {
            var groupFindings = group.ToList();
            if (groupFindings.Count < 2)
                continue;

            // TemporalSequence: consecutive findings on the same host (time-ordered)
            var sorted = groupFindings.OrderBy(f => f.TimeRangeStart).ToList();
            for (int i = 0; i < sorted.Count - 1; i++)
            {
                var from = sorted[i];
                var to = sorted[i + 1];
                if (from.Id == to.Id)
                    continue;
                if (IsPostureFinding(from) || IsPostureFinding(to))
                    continue;
                if (connectedPairs.Contains((from.Id, to.Id)) || connectedPairs.Contains((to.Id, from.Id)))
                    continue;

                var gap = GetTimeGapHours(from, to);
                if (gap > MaxGapHours)
                    continue;

                var narrative = gap <= 0.0
                    ? $"{from.Category} on {from.SourceHost} overlapped with {to.Category}."
                    : gap < 1.0
                        ? $"{from.Category} on {from.SourceHost} was followed by {to.Category} within {gap * 60:F0} minutes."
                        : $"{from.Category} on {from.SourceHost} was followed by {to.Category} within {gap:F1} hours.";

                edges.Add(new CorrelationEdge(
                    from.Id,
                    to.Id,
                    CorrelationType.TemporalSequence,
                    narrative,
                    gap <= 1.0 ? CorrelationConfidence.High : CorrelationConfidence.Medium));

                connectedPairs.Add((from.Id, to.Id));
            }

            // SameHost: findings on the same host targeting the same resource but different categories
            var byTarget = groupFindings
                .Where(f => !string.IsNullOrEmpty(f.Target))
                .GroupBy(f => f.Target, StringComparer.OrdinalIgnoreCase);

            foreach (var targetGroup in byTarget)
            {
                var targetFindings = targetGroup.ToList();
                if (targetFindings.Count < 2)
                    continue;

                for (int i = 0; i < targetFindings.Count; i++)
                {
                    for (int j = i + 1; j < targetFindings.Count; j++)
                    {
                        var a = targetFindings[i];
                        var b = targetFindings[j];
                        if (a.Id == b.Id)
                            continue;
                        if (string.Equals(a.Category, b.Category, StringComparison.OrdinalIgnoreCase))
                            continue; // same category = not a cross-category SameHost link
                        if (connectedPairs.Contains((a.Id, b.Id)) || connectedPairs.Contains((b.Id, a.Id)))
                            continue;

                        var (from, to) = a.TimeRangeStart <= b.TimeRangeStart ? (a, b) : (b, a);

                        edges.Add(new CorrelationEdge(
                            from.Id,
                            to.Id,
                            CorrelationType.SameHost,
                            $"{from.Category} and {to.Category} both affected {from.Target} on {from.SourceHost}.",
                            CorrelationConfidence.Medium));

                        connectedPairs.Add((from.Id, to.Id));
                    }
                }
            }
        }

        // Remove duplicate edges (same direction, same pair of findings)
        var deduped = edges
            .GroupBy(e => (e.FromFindingId, e.ToFindingId))
            .Select(g => g.First())
            .ToList();

        return new TraceMapResult
        {
            Findings = findings,
            Edges = deduped,
            CriticalChains = criticalChains
        };
    }

    private static List<CorrelationEdge> FindEdgesForPair(
        IReadOnlyList<Finding> groupFindings,
        string categoryA,
        string categoryB,
        CorrelationType correlationType)
    {
        var edges = new List<CorrelationEdge>();
        var findingsA = groupFindings.Where(f => IsCategory(f, categoryA)).ToList();
        var findingsB = groupFindings.Where(f => IsCategory(f, categoryB)).ToList();

        if (findingsA.Count == 0 || findingsB.Count == 0)
            return edges;

        // Sort both lists by start time for efficient pairing
        var sortedA = findingsA.OrderBy(f => f.TimeRangeStart).ToList();
        var sortedB = findingsB.OrderBy(f => f.TimeRangeStart).ToList();

        foreach (var fa in sortedA)
        {
            foreach (var fb in sortedB)
            {
                var gap = GetTimeGapHours(fa, fb);
                if (gap > MaxGapHours)
                    continue;

                // Determine direction: earlier → later
                var (from, to) = fa.TimeRangeStart <= fb.TimeRangeStart ? (fa, fb) : (fb, fa);

                // Narrative always matches the actual chronological direction
                var narrative = gap <= 0.0
                    ? $"{from.Category} on {from.SourceHost} overlapped with {to.Category}."
                    : gap < 1.0
                        ? $"{from.Category} on {from.SourceHost} was followed by {to.Category} within {gap * 60:F0} minutes."
                        : $"{from.Category} on {from.SourceHost} was followed by {to.Category} within {gap:F1} hours.";

                var confidence = gap switch
                {
                    <= 0.0 => CorrelationConfidence.High,   // overlapping
                    <= 1.0 => CorrelationConfidence.High,   // within 1 hour
                    <= 6.0 => CorrelationConfidence.Medium, // within 6 hours
                    _ => CorrelationConfidence.Low           // within 24 hours
                };

                edges.Add(new CorrelationEdge(
                    from.Id,
                    to.Id,
                    correlationType,
                    narrative,
                    confidence));
            }
        }

        return edges;
    }

    private static double GetTimeGapHours(Finding a, Finding b)
    {
        if (a.TimeRangeEnd >= b.TimeRangeStart && b.TimeRangeEnd >= a.TimeRangeStart)
            return 0;

        if (a.TimeRangeEnd < b.TimeRangeStart)
            return (b.TimeRangeStart - a.TimeRangeEnd).TotalHours;

        return (a.TimeRangeStart - b.TimeRangeEnd).TotalHours;
    }

    private static bool IsCategory(Finding f, string category) =>
        string.Equals(f.Category, category, StringComparison.OrdinalIgnoreCase);

    private static bool IsPostureFinding(Finding finding) =>
        !string.IsNullOrWhiteSpace(finding.RuleId);
}
