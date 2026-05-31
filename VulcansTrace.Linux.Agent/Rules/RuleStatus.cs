namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Detailed outcome of a single rule evaluation.
/// </summary>
public enum RuleStatus
{
    /// <summary>The rule passed its security check.</summary>
    Passed,

    /// <summary>The rule failed its security check and produced an active finding.</summary>
    Failed,

    /// <summary>The rule failed but the finding was suppressed by user configuration.</summary>
    Suppressed,

    /// <summary>The rule could not be evaluated because of an unexpected exception.</summary>
    Crashed,

    /// <summary>The rule does not apply to this system (e.g., hardware-dependent check on incompatible hardware).</summary>
    NotApplicable
}
