using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A rule that can accept per-role policy context during evaluation.
/// </summary>
public interface IContextualRule : IRule
{
    /// <summary>
    /// Evaluates the provided scan data using the given role context.
    /// </summary>
    /// <param name="data">The aggregated system scan data.</param>
    /// <param name="context">The role and policy context.</param>
    /// <returns>The result of the evaluation.</returns>
    RuleResult Evaluate(ScanData data, RuleEvaluationContext context);
}
