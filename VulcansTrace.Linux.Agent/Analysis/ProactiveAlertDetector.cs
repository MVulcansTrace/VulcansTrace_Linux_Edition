using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Detects findings that have returned after a previous verified fix,
/// so the agent can volunteer the regression in the narrative.
/// </summary>
public sealed class ProactiveAlertDetector
{
    /// <summary>
    /// Returns alerts for current findings whose rule was previously verified fixed.
    /// </summary>
    public IReadOnlyList<ProactiveAlert> Detect(
        IReadOnlyList<Finding> findings,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory,
        DateTime referenceUtc)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(ruleHistory);

        var alerts = new List<ProactiveAlert>();

        var currentRuleIds = findings
            .Where(f => !string.IsNullOrWhiteSpace(f.RuleId))
            .GroupBy(f => f.RuleId!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new
            {
                RuleId = g.Key,
                Representative = g.OrderByDescending(f => f.Severity).First()
            });

        foreach (var rule in currentRuleIds)
        {
            if (!ruleHistory.TryGetValue(rule.RuleId, out var entry))
                continue;

            if (!entry.LastVerifiedFixedUtc.HasValue)
                continue;

            var lastVerified = entry.LastVerifiedFixedUtc.Value;

            // A finding cannot have returned before or during the audit that verified it fixed.
            if (referenceUtc <= lastVerified)
                continue;

            var daysSince = (int)Math.Floor((referenceUtc - lastVerified).TotalDays);

            alerts.Add(new ProactiveAlert
            {
                RuleId = rule.RuleId,
                LastVerifiedFixedUtc = lastVerified,
                DaysSinceVerifiedFixed = Math.Max(0, daysSince),
                CurrentSeverity = rule.Representative.Severity,
                Guidance = RuleCategoryResolver.GetRegressionGuidance(rule.RuleId)
            });
        }

        return alerts;
    }
}
