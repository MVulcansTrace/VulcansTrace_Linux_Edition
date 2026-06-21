using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Resolves a query reference against the conversation entity frame.
/// Handles bare category words (e.g. "SSH") by preferring the focused finding when its category
/// matches, so follow-ups like "explain SSH" or "show evidence SSH" consistently resolve to the
/// finding already under discussion.
/// </summary>
internal static class ReferenceResolver
{
    private static readonly Regex RuleIdPattern = new(
        @"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-\d+$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Returns the effective reference for a query. If the query names a bare category word and
    /// the focused finding belongs to that category, the focused finding's rule ID is returned so
    /// the conversation stays on the same subject. Otherwise the explicit target reference or the
    /// last focused rule/finding is returned.
    /// </summary>
    public static string? ResolveReference(AgentQuery query, EntityFrame entities)
    {
        if (string.IsNullOrWhiteSpace(query.TargetReference))
        {
            return entities.LastRuleId ?? entities.LastFinding?.RuleId;
        }

        var reference = query.TargetReference;

        // If the user named a category (not a rule ID) and the focused finding is of that same
        // category, prefer the focused finding over an arbitrary category match.
        if (entities.LastFinding != null
            && IsBareCategoryWord(reference)
            && entities.LastFinding.Category.Equals(reference, StringComparison.OrdinalIgnoreCase))
        {
            return entities.LastFinding.RuleId;
        }

        return reference;
    }

    /// <summary>
    /// Rule IDs are dash-separated alphanumeric segments ending in a numeric segment
    /// (e.g. "FW-002", "K8S-002", "PKG-VULN-001"). Anything else is treated as a
    /// natural-language category word (e.g. "SSH", "firewall").
    /// </summary>
    private static bool IsBareCategoryWord(string reference)
    {
        return !RuleIdPattern.IsMatch(reference);
    }
}
