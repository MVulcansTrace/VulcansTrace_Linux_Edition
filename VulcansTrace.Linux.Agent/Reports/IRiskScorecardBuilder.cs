using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="RiskScorecard"/> from a collection of findings.
/// </summary>
public interface IRiskScorecardBuilder
{
    /// <summary>
    /// Builds a risk scorecard from the given findings.
    /// </summary>
    /// <param name="findings">The findings to evaluate.</param>
    /// <param name="timestamp">Optional timestamp for the scorecard.</param>
    /// <returns>A risk scorecard, or <c>null</c> if no findings are provided.</returns>
    RiskScorecard? Build(IReadOnlyList<Finding> findings, DateTime? timestamp = null);
}
