using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Limits a set of remediation findings to the rule-id prefixes a schedule is allowed to
/// remediate, and parses the comma-separated prefix list supplied by operators. Shared by the
/// CLI and UI so that the scope advertised to the user is the scope actually enforced.
/// </summary>
public static class RemediationScopeFilter
{
    /// <summary>
    /// Parses a comma-separated list of rule-id prefixes into a normalized, de-duplicated list.
    /// </summary>
    /// <param name="value">The raw value (e.g. <c>"FW, KERN"</c>).</param>
    /// <returns>Upper-cased, trimmed, distinct prefixes; empty if <paramref name="value"/> is blank.</returns>
    public static IReadOnlyList<string> ParsePrefixes(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();

        return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.ToUpperInvariant())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Returns only the findings whose leading rule-id namespace token matches one of the
    /// allowed prefixes. When <paramref name="prefixes"/> is null or empty, every finding is
    /// returned (empty scope = all rules).
    /// </summary>
    /// <param name="findings">The findings to filter.</param>
    /// <param name="prefixes">The allowed rule-id prefixes, or null/empty for all.</param>
    /// <returns>The findings in scope.</returns>
    /// <remarks>
    /// Matching is token-based rather than a raw <see cref="string.StartsWith(string)"/> so that a
    /// short prefix cannot accidentally span namespaces: a prefix of <c>K</c> matches neither
    /// <c>KERN-001</c> nor <c>K8S-002</c>. Only findings whose first segment (split on
    /// <c>-</c>, <c>_</c>, or <c>.</c>) equals a configured prefix are kept.
    /// </remarks>
    public static IReadOnlyList<Finding> Apply(IReadOnlyList<Finding> findings, IReadOnlyList<string>? prefixes)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (prefixes is null || prefixes.Count == 0)
            return findings;

        var allowed = prefixes
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim().ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (allowed.Count == 0)
            return findings;

        return findings
            .Where(f => !string.IsNullOrWhiteSpace(f.RuleId) && allowed.Contains(GetRuleToken(f.RuleId!)))
            .ToList();
    }

    private static string GetRuleToken(string ruleId)
    {
        var span = ruleId.AsSpan();
        var separatorIndex = span.IndexOfAny('-', '_', '.');
        return separatorIndex < 0
            ? ruleId.ToUpperInvariant()
            : span[..separatorIndex].ToString().ToUpperInvariant();
    }
}
