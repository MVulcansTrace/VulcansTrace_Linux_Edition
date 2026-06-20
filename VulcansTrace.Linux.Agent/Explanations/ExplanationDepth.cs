namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Depth tier for a single-rule explanation.
/// Determined from the rule's retained memory history: snapshot count,
/// remediation cycles, and severity trend.
/// </summary>
public enum ExplanationDepth
{
    /// <summary>No meaningful history; use the standard concise explanation.</summary>
    Standard,

    /// <summary>Seen in multiple audits but not recurring or worsening; add brief continuity.</summary>
    Familiar,

    /// <summary>Completed two or more remediation cycles; add systemic root-cause guidance.</summary>
    Recurring,

    /// <summary>Severity is worsening; add escalation timeline and what changed.</summary>
    Escalating
}
