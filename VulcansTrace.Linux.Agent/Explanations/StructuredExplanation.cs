namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// A structured breakdown of a security finding explanation.
/// </summary>
public sealed record StructuredExplanation
{
    /// <summary>What the rule detected.</summary>
    public string WhatWasFound { get; init; } = string.Empty;

    /// <summary>Why the finding matters from a security perspective.</summary>
    public string WhyItMatters { get; init; } = string.Empty;

    /// <summary>How an administrator can independently verify the finding.</summary>
    public string HowToVerify { get; init; } = string.Empty;

    /// <summary>Suggested next steps or remediation commands (preview only, not auto-executed).</summary>
    public string SuggestedNextAction { get; init; } = string.Empty;

    /// <summary>Preconditions that should be met before applying remediation.</summary>
    public string Preconditions { get; init; } = string.Empty;

    /// <summary>Commands to back up configuration or state before making changes.</summary>
    public string BackupCommands { get; init; } = string.Empty;

    /// <summary>Commands to roll back the remediation if something goes wrong.</summary>
    public string RollbackCommands { get; init; } = string.Empty;

    /// <summary>Confidence level derived from the rule severity.</summary>
    public string Confidence { get; init; } = string.Empty;

    /// <summary>Caveats, edge cases, or context that affects interpretation.</summary>
    public string Caveats { get; init; } = string.Empty;
}
