namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Result and metadata produced by evaluating one rule.
/// </summary>
internal sealed record SingleRuleEvaluationResult(
    RuleResult RuleResult,
    IReadOnlyList<string> Warnings,
    bool DisabledByPolicy);
