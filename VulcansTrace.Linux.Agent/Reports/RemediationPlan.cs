namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// A complete remediation plan generated from agent findings.
/// </summary>
public sealed record RemediationPlan
{
    /// <summary>UTC timestamp when the plan was generated.</summary>
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Individual sections, one per finding.</summary>
    public IReadOnlyList<RemediationSection> Sections { get; init; } = Array.Empty<RemediationSection>();

    /// <summary>Total number of sections in the plan.</summary>
    public int TotalSections => Sections.Count;
}

/// <summary>
/// A single section of the remediation plan corresponding to one finding.
/// </summary>
public sealed record RemediationSection
{
    /// <summary>The rule identifier.</summary>
    public required string RuleId { get; init; }

    /// <summary>Brief description of the finding.</summary>
    public required string FindingSummary { get; init; }

    /// <summary>Risk level/notes for this finding.</summary>
    public required string RiskNote { get; init; }

    /// <summary>Remediation commands to run, with safety classifications.</summary>
    public IReadOnlyList<RemediationCommand> RemediationCommands { get; init; } = Array.Empty<RemediationCommand>();

    /// <summary>Hints for rolling back the remediation.</summary>
    public IReadOnlyList<string> RollbackHints { get; init; } = Array.Empty<string>();

    /// <summary>Verification commands to confirm the fix, with safety classifications.</summary>
    public IReadOnlyList<RemediationCommand> VerificationCommands { get; init; } = Array.Empty<RemediationCommand>();
}

/// <summary>
/// A single command in a remediation plan with its safety classification.
/// </summary>
public sealed record RemediationCommand
{
    /// <summary>The command text.</summary>
    public required string Command { get; init; }

    /// <summary>Safety classification of the command.</summary>
    public Explanations.CommandSafety Safety { get; init; } = Explanations.CommandSafety.Unknown;
}
