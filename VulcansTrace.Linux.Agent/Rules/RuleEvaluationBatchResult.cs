namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Results and warnings produced by evaluating a set of rules.
/// </summary>
internal sealed record RuleEvaluationBatchResult(
    IReadOnlyList<RuleResult> RuleResults,
    IReadOnlyList<string> Warnings);
