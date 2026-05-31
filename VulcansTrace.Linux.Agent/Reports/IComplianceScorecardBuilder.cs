using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="ComplianceScorecard"/> from agent rule results and optional audit history.
/// </summary>
public interface IComplianceScorecardBuilder
{
    /// <summary>
    /// Builds a compliance scorecard from the given rule results and history store.
    /// </summary>
    /// <param name="ruleResults">All rule results from the audit.</param>
    /// <param name="historyStore">Optional history store for trend data.</param>
    /// <param name="timestamp">Timestamp for the scorecard.</param>
    /// <returns>A compliance scorecard, or null if no rules have CIS mappings.</returns>
    ComplianceScorecard? Build(
        IReadOnlyList<RuleResult> ruleResults,
        IAuditHistoryStore? historyStore = null,
        DateTime? timestamp = null);
}
