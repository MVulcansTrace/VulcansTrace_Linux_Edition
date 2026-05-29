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

    /// <summary>Remediation commands to run.</summary>
    public IReadOnlyList<string> RemediationCommands { get; init; } = Array.Empty<string>();

    /// <summary>Hints for rolling back the remediation.</summary>
    public IReadOnlyList<string> RollbackHints { get; init; } = Array.Empty<string>();

    /// <summary>Verification commands to confirm the fix.</summary>
    public IReadOnlyList<string> VerificationCommands { get; init; } = Array.Empty<string>();
}
