namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Describes how a rule's severity has changed over recent audits.
/// </summary>
public enum RuleStatusTrend
{
    /// <summary>The rule has not been seen before.</summary>
    New,

    /// <summary>The rule's severity has not changed.</summary>
    Stable,

    /// <summary>The rule's severity has decreased (finding is less severe or fixed).</summary>
    Improving,

    /// <summary>The rule's severity has increased.</summary>
    Worsening
}
