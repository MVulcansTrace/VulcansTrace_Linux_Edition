namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Represents the structured intent derived from a user's natural language query.
/// </summary>
public enum AgentIntent
{
    /// <summary>Comprehensive system security audit.</summary>
    FullAudit,

    /// <summary>Focus on firewall configuration and rules.</summary>
    FirewallCheck,

    /// <summary>Focus on network interfaces, routes, and connections.</summary>
    NetworkCheck,

    /// <summary>Focus on running system services.</summary>
    ServiceCheck,

    /// <summary>Focus on open ports and listening services.</summary>
    PortCheck,

    /// <summary>Request explanation of a previous finding.</summary>
    ExplainFinding,

    /// <summary>Show what changed since the last audit.</summary>
    ShowChanges,

    /// <summary>Explain why critical/high findings matter.</summary>
    ExplainCritical,

    /// <summary>Filter the last result to a specific category.</summary>
    FilterCategory,

    /// <summary>Prioritize findings into a remediation plan.</summary>
    PrioritizeRemediation,

    /// <summary>List suppressed findings from the last result.</summary>
    ListSuppressed,

    /// <summary>Request help on available capabilities.</summary>
    Help
}
