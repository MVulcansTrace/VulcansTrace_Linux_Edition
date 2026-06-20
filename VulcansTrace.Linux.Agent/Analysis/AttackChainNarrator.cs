using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Builds deterministic attack-chain narratives from posture-backed finding relationships.
/// </summary>
public sealed class AttackChainNarrator
{
    /// <summary>
    /// Maximum number of attack chains to surface.
    /// </summary>
    internal const int MaxChains = 3;

    private static readonly IReadOnlyList<ContinuationEdge> KnownContinuationEdges = new[]
    {
        new ContinuationEdge("SSH-002", "SSH-001"),
        new ContinuationEdge("SSH-002", "SSH-005"),
    };

    /// <summary>
    /// Builds attack chains from the provided findings and correlations.
    /// </summary>
    public IReadOnlyList<AttackChain> BuildChains(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<PostureCorrelation> correlations)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(correlations);

        var links = findings
            .Select(BuildLink)
            .Where(link => link != null)
            .Select(link => link!)
            .GroupBy(link => link.RuleId, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(link => link.Severity).First())
            .ToDictionary(link => link.RuleId, link => link, StringComparer.OrdinalIgnoreCase);

        if (links.Count < 2)
            return Array.Empty<AttackChain>();

        var continuationGraph = BuildContinuationGraph();
        var chains = new List<IReadOnlyList<AttackChainLink>>();
        foreach (var correlation in correlations)
        {
            if (!links.TryGetValue(correlation.RuleIdA, out var linkA)
                || !links.TryGetValue(correlation.RuleIdB, out var linkB))
                continue;

            var chain = OrderCorrelatedPair(linkA, linkB);
            if (chain.Count < 2)
                continue;

            chains.AddRange(TraverseContinuations(chain, links, continuationGraph));
        }

        return chains
            .DistinctBy(c => string.Join("|", c.Select(link => link.RuleId)), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(c => c.Max(link => link.Severity))
            .ThenByDescending(c => c.Count)
            .Take(MaxChains)
            .Select((c, index) => BuildAttackChain(c, correlations, index))
            .ToList();
    }

    private static AttackChainLink? BuildLink(Finding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.RuleId))
            return null;

        var mapping = AttackChainStageMapping.GetMapping(finding.RuleId);
        if (mapping == null)
            return null;

        return new AttackChainLink
        {
            RuleId = finding.RuleId,
            FindingId = finding.Id,
            Stage = mapping.Stage,
            StageName = StageDisplayName(mapping.Stage),
            Severity = finding.Severity,
            MitreTechniqueIds = finding.MitreTechniques.Select(t => t.TechniqueId).ToList(),
            Rationale = mapping.Rationale
        };
    }

    private static IReadOnlyList<AttackChainLink> OrderCorrelatedPair(AttackChainLink linkA, AttackChainLink linkB)
    {
        if (linkA.Stage == linkB.Stage)
            return Array.Empty<AttackChainLink>();

        return linkA.Stage < linkB.Stage
            ? new[] { linkA, linkB }
            : new[] { linkB, linkA };
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> BuildContinuationGraph()
    {
        return KnownContinuationEdges
            .GroupBy(edge => edge.FromRulePattern, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group.Select(edge => edge.ToRulePattern).ToList(),
                StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<IReadOnlyList<AttackChainLink>> TraverseContinuations(
        IReadOnlyList<AttackChainLink> seed,
        IReadOnlyDictionary<string, AttackChainLink> links,
        IReadOnlyDictionary<string, IReadOnlyList<string>> continuationGraph)
    {
        var chains = new List<IReadOnlyList<AttackChainLink>>();
        Traverse(seed.ToList(), links, continuationGraph, chains);
        return chains;
    }

    private static void Traverse(
        List<AttackChainLink> current,
        IReadOnlyDictionary<string, AttackChainLink> links,
        IReadOnlyDictionary<string, IReadOnlyList<string>> continuationGraph,
        List<IReadOnlyList<AttackChainLink>> chains)
    {
        var extended = false;
        var last = current[^1];

        foreach (var kvp in continuationGraph)
        {
            if (!Matches(last.RuleId, kvp.Key))
                continue;

            foreach (var nextPattern in kvp.Value)
            {
                var next = FindLink(nextPattern, links);
                if (next == null || current.Any(link => link.RuleId.Equals(next.RuleId, StringComparison.OrdinalIgnoreCase)))
                    continue;

                if (last.Stage >= next.Stage)
                    continue;

                var candidate = current.ToList();
                candidate.Add(next);
                Traverse(candidate, links, continuationGraph, chains);
                extended = true;
            }
        }

        if (!extended)
        {
            chains.Add(current);
        }
    }

    private static AttackChainLink? FindLink(string pattern, IReadOnlyDictionary<string, AttackChainLink> links)
    {
        foreach (var link in links.Values)
        {
            if (Matches(link.RuleId, pattern))
                return link;
        }

        return null;
    }

    private static bool Matches(string ruleId, string pattern)
    {
        if (pattern.EndsWith("*", StringComparison.Ordinal))
            return ruleId.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase);

        return ruleId.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static AttackChain BuildAttackChain(IReadOnlyList<AttackChainLink> links, IReadOnlyList<PostureCorrelation> correlations, int narrativeIndex)
    {
        var narrative = BuildNarrative(links, narrativeIndex);
        var ruleIds = links.Select(l => l.RuleId).ToList();
        var maxSeverity = links.Max(l => l.Severity);

        var sourcePatternIds = correlations
            .Where(c => ruleIds.Contains(c.RuleIdA, StringComparer.OrdinalIgnoreCase)
                && ruleIds.Contains(c.RuleIdB, StringComparer.OrdinalIgnoreCase))
            .Select(c => c.PatternId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AttackChain
        {
            Links = links,
            CombinedSeverity = maxSeverity,
            Narrative = narrative,
            RuleIds = ruleIds,
            SourcePatternIds = sourcePatternIds
        };
    }

    private static string BuildNarrative(IReadOnlyList<AttackChainLink> links, int narrativeIndex)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(OpeningFor(narrativeIndex));

        for (var i = 0; i < links.Count; i++)
        {
            var link = links[i];
            sb.Append($"**[{link.RuleId}]** {link.Rationale}");

            var mitreText = link.MitreTechniqueIds.Count > 0
                ? $" ({string.Join(", ", link.MitreTechniqueIds)})"
                : string.Empty;
            sb.Append(mitreText);

            if (i < links.Count - 1)
            {
                sb.Append(" → ");
            }
        }

        sb.Append(". Fix any one link and the chain breaks.");
        return sb.ToString();
    }

    private static string OpeningFor(int narrativeIndex) => narrativeIndex switch
    {
        0 => "This is one attack chain: ",
        1 => "Another attack chain: ",
        2 => "A third attack chain: ",
        _ => "Another attack chain: "
    };

    private static string StageDisplayName(AttackChainStage stage) => stage switch
    {
        AttackChainStage.Reconnaissance => "Reconnaissance",
        AttackChainStage.InitialAccess => "Initial Access",
        AttackChainStage.CredentialAccess => "Credential Access",
        AttackChainStage.Execution => "Execution",
        AttackChainStage.LateralMovement => "Lateral Movement",
        AttackChainStage.Exfiltration => "Exfiltration",
        _ => stage.ToString()
    };

    private sealed record ContinuationEdge(string FromRulePattern, string ToRulePattern);
}
