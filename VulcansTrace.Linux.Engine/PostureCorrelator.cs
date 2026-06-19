using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Default implementation of <see cref="IPostureCorrelator"/>.
/// Matches findings against a registry of declarative posture correlation patterns.
/// </summary>
public sealed class PostureCorrelator : IPostureCorrelator
{
    private readonly IReadOnlyList<PostureCorrelationPattern> _patterns;

    /// <summary>
    /// Initializes a new <see cref="PostureCorrelator"/> with the default pattern registry.
    /// </summary>
    public PostureCorrelator()
        : this(DefaultPatterns())
    {
    }

    /// <summary>
    /// Initializes a new <see cref="PostureCorrelator"/> with a custom pattern registry.
    /// </summary>
    public PostureCorrelator(IEnumerable<PostureCorrelationPattern> patterns)
    {
        _patterns = patterns?.ToList() ?? throw new ArgumentNullException(nameof(patterns));
    }

    /// <inheritdoc />
    public IReadOnlyList<PostureCorrelation> Correlate(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return Array.Empty<PostureCorrelation>();

        var correlations = new List<PostureCorrelation>();
        var byRuleId = findings
            .Where(f => !string.IsNullOrWhiteSpace(f.RuleId))
            .GroupBy(f => f.RuleId!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var emittedKeys = new HashSet<(string PatternId, string RuleIdA, string RuleIdB)>();

        foreach (var pattern in _patterns)
        {
            var matchesA = FindMatches(pattern.RuleIdA, byRuleId);
            var matchesB = FindMatches(pattern.RuleIdB, byRuleId);

            if (matchesA.Count == 0 || matchesB.Count == 0)
                continue;

            foreach (var findingA in matchesA)
            {
                foreach (var findingB in matchesB)
                {
                    // Avoid correlating a finding with itself.
                    if (findingA.Id == findingB.Id)
                        continue;

                    var ruleA = findingA.RuleId!;
                    var ruleB = findingB.RuleId!;
                    var key = (pattern.PatternId, ruleA, ruleB);

                    if (!emittedKeys.Add(key))
                        continue;

                    var narrative = pattern.NarrativeTemplate
                        .Replace("{RuleIdA}", ruleA, StringComparison.OrdinalIgnoreCase)
                        .Replace("{RuleIdB}", ruleB, StringComparison.OrdinalIgnoreCase);

                    correlations.Add(new PostureCorrelation
                    {
                        PatternId = pattern.PatternId,
                        RuleIdA = ruleA,
                        RuleIdB = ruleB,
                        Narrative = narrative,
                        CombinedSeverity = pattern.CombinedSeverity,
                        MatchedFindingRuleIds = new[] { ruleA, ruleB },
                        FindingIds = new[] { findingA.Id, findingB.Id }
                    });
                }
            }
        }

        return correlations;
    }

    private static IReadOnlyList<Finding> FindMatches(string ruleIdPattern, IReadOnlyDictionary<string, List<Finding>> byRuleId)
    {
        if (ruleIdPattern.EndsWith("*", StringComparison.Ordinal))
        {
            var prefix = ruleIdPattern[..^1];
            if (string.IsNullOrEmpty(prefix))
                return Array.Empty<Finding>();

            return byRuleId
                .Where(kvp => kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .SelectMany(kvp => kvp.Value)
                .ToList();
        }

        if (byRuleId.TryGetValue(ruleIdPattern, out var findings))
            return findings;

        return Array.Empty<Finding>();
    }

    /// <summary>
    /// Returns the default registry of posture correlation patterns.
    /// </summary>
    public static IReadOnlyList<PostureCorrelationPattern> DefaultPatterns() => new List<PostureCorrelationPattern>
    {
        new()
        {
            PatternId = "POSTURE-001",
            RuleIdA = "FW-002",
            RuleIdB = "SSH-002",
            CombinedSeverity = Severity.Critical,
            NarrativeTemplate =
                "{RuleIdA} allows SSH from anywhere and {RuleIdB} has password authentication enabled. " +
                "Either one alone is risky; together they create a straight path to root access."
        },
        new()
        {
            PatternId = "POSTURE-002",
            RuleIdA = "FW-004",
            RuleIdB = "PORT-*",
            CombinedSeverity = Severity.High,
            NarrativeTemplate =
                "{RuleIdA} found no active firewall, and {RuleIdB} exposes listening service ports. " +
                "Without a firewall, those ports are reachable from any source."
        },
        new()
        {
            PatternId = "POSTURE-003",
            RuleIdA = "USER-001",
            RuleIdB = "SSH-002",
            CombinedSeverity = Severity.Critical,
            NarrativeTemplate =
                "{RuleIdA} indicates a weak password policy and {RuleIdB} allows password-based SSH. " +
                "Weak passwords plus remote password login is a direct brute-force path."
        }
    };
}
