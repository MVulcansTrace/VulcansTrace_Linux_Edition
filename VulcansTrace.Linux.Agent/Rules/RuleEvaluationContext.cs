namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Context passed to contextual rules during evaluation.
/// </summary>
public sealed record RuleEvaluationContext(MachineRole Role, RulePolicy? Policy);
