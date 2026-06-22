namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Whether a user-reported step outcome succeeded or failed.
/// </summary>
public enum StepOutcomeKind
{
    Success,
    Failure
}

/// <summary>
/// A structured report of a user-reported remediation step outcome.
/// </summary>
public sealed record StepOutcomeReport
{
    /// <summary>Whether the step succeeded or failed.</summary>
    public StepOutcomeKind Kind { get; init; }

    /// <summary>1-based step ordinal if the user referenced "step N".</summary>
    public int? StepOrdinal { get; init; }

    /// <summary>Explicit rule ID if the user referenced one (e.g. "FW-001 failed").</summary>
    public string? RuleId { get; init; }

    /// <summary>Raw failure reason or error text supplied by the user.</summary>
    public string? FailureReason { get; init; }

    /// <summary>True when the report explicitly references a step.</summary>
    public bool HasExplicitReference => StepOrdinal.HasValue || !string.IsNullOrWhiteSpace(RuleId);
}
