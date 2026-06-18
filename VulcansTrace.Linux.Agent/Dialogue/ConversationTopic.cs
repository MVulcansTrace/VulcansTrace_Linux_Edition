namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// High-level topic of the current conversation turn.
/// Used to drive intent inference and response templating.
/// </summary>
public enum ConversationTopic
{
    /// <summary>Initial state or generic help.</summary>
    Unknown,

    /// <summary>Running an audit or reviewing audit results.</summary>
    Audit,

    /// <summary>Explaining a specific finding or rule.</summary>
    Explanation,

    /// <summary>Remediation planning, sessions, or verification.</summary>
    Remediation,

    /// <summary>Comparing audits, baselines, or drift.</summary>
    Comparison,

    /// <summary>Baseline and drift operations.</summary>
    Drift,

    /// <summary>Help or capability questions.</summary>
    Help
}
