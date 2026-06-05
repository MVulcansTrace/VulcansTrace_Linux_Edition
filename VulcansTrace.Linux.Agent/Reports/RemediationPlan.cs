using VulcansTrace.Linux.Core;

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

    /// <summary>MITRE ATT&CK techniques mapped to the underlying finding.</summary>
    public IReadOnlyList<MitreTechnique> MitreTechniques { get; init; } = Array.Empty<MitreTechnique>();

    /// <summary>Preconditions that should be satisfied before applying this section.</summary>
    public IReadOnlyList<string> Preconditions { get; init; } = Array.Empty<string>();

    /// <summary>Backup commands to preserve state before making changes.</summary>
    public IReadOnlyList<RemediationCommand> BackupCommands { get; init; } = Array.Empty<RemediationCommand>();

    /// <summary>Apply commands to remediate the finding, with safety classifications.</summary>
    public IReadOnlyList<RemediationCommand> ApplyCommands { get; init; } = Array.Empty<RemediationCommand>();

    /// <summary>Concrete rollback commands to undo the remediation, with safety classifications.</summary>
    public IReadOnlyList<RemediationCommand> RollbackCommands { get; init; } = Array.Empty<RemediationCommand>();

    /// <summary>Hints for rolling back the remediation.</summary>
    public IReadOnlyList<string> RollbackHints { get; init; } = Array.Empty<string>();

    /// <summary>Verification commands to confirm the fix, with safety classifications.</summary>
    public IReadOnlyList<RemediationCommand> VerificationCommands { get; init; } = Array.Empty<RemediationCommand>();

    /// <summary>Active countermeasure commands for incident response playbooks.</summary>
    public IReadOnlyList<CountermeasureCommand> CountermeasureCommands { get; init; } = Array.Empty<CountermeasureCommand>();

    /// <summary>
    /// Whether rollback guidance was explicitly provided in the explanation template.
    /// False when only generic category-based fallback hints are available.
    /// </summary>
    public bool HasExplicitRollbackGuidance { get; init; }

    /// <summary>
    /// Compact preview of expected impact, rollback path, and verification command
    /// shown before the user copies or executes apply commands.
    /// </summary>
    public RemediationImpactPreview? ImpactPreview { get; init; }
}

/// <summary>
/// A compact preview of expected impact, rollback path, and verification command
/// for a single remediation section.
/// </summary>
public sealed record RemediationImpactPreview
{
    /// <summary>What will change when the apply commands are executed.</summary>
    public string ExpectedImpact { get; init; } = string.Empty;

    /// <summary>Where the expected impact text came from.</summary>
    public RemediationImpactSource ExpectedImpactSource { get; init; } = RemediationImpactSource.Generic;

    /// <summary>How to undo the remediation if something goes wrong.</summary>
    public string RollbackPath { get; init; } = string.Empty;

    /// <summary>Whether the rollback path is a command, explicit hint, generic hint, or fallback text.</summary>
    public RemediationPreviewTextKind RollbackPathKind { get; init; } = RemediationPreviewTextKind.ManualFallback;

    /// <summary>Command to run to confirm the fix was applied correctly.</summary>
    public string VerificationCommand { get; init; } = string.Empty;

    /// <summary>True when <see cref="VerificationCommand"/> is an actual shell command.</summary>
    public bool IsVerificationCommand { get; init; }

    /// <summary>Whether the verification text is a command or fallback guidance.</summary>
    public RemediationPreviewTextKind VerificationKind { get; init; } = RemediationPreviewTextKind.ManualFallback;
}

/// <summary>
/// Indicates where the expected impact text in a remediation preview came from.
/// </summary>
public enum RemediationImpactSource
{
    /// <summary>Impact was summarized from the suggested apply action text.</summary>
    SuggestedAction,

    /// <summary>Impact was inferred only from the number of apply commands.</summary>
    ApplyCommands,

    /// <summary>Impact fell back to the finding summary/details.</summary>
    Finding,

    /// <summary>Impact is generic fallback text.</summary>
    Generic
}

/// <summary>
/// Indicates how a compact preview text should be interpreted by renderers.
/// </summary>
public enum RemediationPreviewTextKind
{
    /// <summary>The text is an executable shell command.</summary>
    Command,

    /// <summary>The text is explicit prose guidance from the remediation explanation.</summary>
    ExplicitGuidance,

    /// <summary>The text is generated category-based fallback guidance.</summary>
    GenericGuidance,

    /// <summary>The text is manual fallback guidance because no better preview data was available.</summary>
    ManualFallback
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

    /// <summary>Detailed structural analysis of the command.</summary>
    public Explanations.CommandAnalysis Analysis { get; init; } = new();
}
