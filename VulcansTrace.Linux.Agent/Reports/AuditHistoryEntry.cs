using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Represents a single entry in the agent audit history.
/// </summary>
public sealed record AuditHistoryEntry
{
    /// <summary>Unique snapshot identifier for this audit.</summary>
    public required string SnapshotId { get; init; }

    /// <summary>UTC timestamp when the audit completed.</summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>The intent/scope of the audit.</summary>
    public required AgentIntent Intent { get; init; }

    /// <summary>Total number of findings.</summary>
    public int TotalFindings { get; init; }

    /// <summary>Number of critical findings.</summary>
    public int CriticalCount { get; init; }

    /// <summary>Number of high findings.</summary>
    public int HighCount { get; init; }

    /// <summary>Number of medium findings.</summary>
    public int MediumCount { get; init; }

    /// <summary>Number of low findings.</summary>
    public int LowCount { get; init; }

    /// <summary>Number of info findings.</summary>
    public int InfoCount { get; init; }

    /// <summary>Number of warnings.</summary>
    public int WarningCount { get; init; }

    /// <summary>Whether the audit was exported.</summary>
    public bool Exported { get; init; }

    /// <summary>Number of rules that passed.</summary>
    public int PassedCount { get; init; }

    /// <summary>Number of rules that failed.</summary>
    public int FailedCount { get; init; }

    /// <summary>Number of findings suppressed by user configuration.</summary>
    public int SuppressedCount { get; init; }

    /// <summary>Number of rules that crashed during evaluation.</summary>
    public int CrashedCount { get; init; }

    /// <summary>Lightweight snapshot of findings for diff comparisons.</summary>
    public IReadOnlyList<AuditSnapshotFinding> SnapshotFindings { get; init; } = Array.Empty<AuditSnapshotFinding>();

    /// <summary>Capability report snapshot for this audit.</summary>
    public string? CapabilityReport { get; init; }

    /// <summary>
    /// Structured data-source capabilities captured during this audit. Persisted so follow-up
    /// intents (e.g. <see cref="AgentIntent.ShowEvidence"/>) can report accurate provenance after
    /// a process restart rehydrates the last result from history.
    /// </summary>
    /// <remarks>
    /// This field increases per-snapshot history size. Older entries are slimmed by the history
    /// store, which empties this field while retaining counts and <see cref="SnapshotFindings"/>.
    /// </remarks>
    public IReadOnlyList<DataSourceCapability> DataSourceCapabilities { get; init; } = Array.Empty<DataSourceCapability>();

    /// <summary>
    /// Attack chains derived from this audit's findings and posture correlations. Persisted so the
    /// <see cref="AgentIntent.ShowEvidence"/> attack-chain-membership section survives a restart/rehydrate.
    /// </summary>
    /// <remarks>
    /// This field increases per-snapshot history size. Older entries are slimmed by the history
    /// store, which empties this field while retaining counts and <see cref="SnapshotFindings"/>.
    /// </remarks>
    public IReadOnlyList<AttackChain> AttackChains { get; init; } = Array.Empty<AttackChain>();

    /// <summary>Detailed rule evaluation results for this audit.</summary>
    /// <remarks>Empty when <see cref="IsSlimSummary"/> is true.</remarks>
    public IReadOnlyList<RuleResult> RuleResults { get; init; } = Array.Empty<RuleResult>();

    /// <summary>Agent warnings produced during this audit.</summary>
    /// <remarks>Empty when <see cref="IsSlimSummary"/> is true.</remarks>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    /// <summary>Optional pasted-log analysis result attached to this audit.</summary>
    /// <remarks>Null when <see cref="IsSlimSummary"/> is true.</remarks>
    public AnalysisResult? LogAnalysisResult { get; init; }

    /// <summary>CIS compliance scorecard snapshot for this audit.</summary>
    public VulcansTrace.Linux.Core.Compliance.ComplianceScorecard? Scorecard { get; init; }

    /// <summary>
    /// True when this entry has been reduced to a slim summary. Verbose fields such as
    /// <see cref="DataSourceCapabilities"/>, <see cref="AttackChains"/>, <see cref="RuleResults"/>,
    /// <see cref="Warnings"/>, and <see cref="LogAnalysisResult"/> are empty in slim entries.
    /// Counts, metadata, <see cref="SnapshotFindings"/>, and <see cref="Scorecard"/> are retained.
    /// </summary>
    public bool IsSlimSummary { get; init; }

    /// <summary>
    /// Returns a slim copy of this entry, preserving only metadata, counts,
    /// <see cref="SnapshotFindings"/>, and <see cref="Scorecard"/>. Dropping verbose fields
    /// keeps the on-disk history bounded even as per-audit metadata grows.
    /// </summary>
    public AuditHistoryEntry ToSlimSummary() => this with
    {
        DataSourceCapabilities = Array.Empty<DataSourceCapability>(),
        AttackChains = Array.Empty<AttackChain>(),
        RuleResults = Array.Empty<RuleResult>(),
        Warnings = Array.Empty<string>(),
        LogAnalysisResult = null,
        IsSlimSummary = true
    };
}

/// <summary>
/// A lightweight snapshot of a single finding for history/diff purposes.
/// </summary>
public sealed record AuditSnapshotFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string Severity { get; init; }
    public string Confidence { get; init; } = DetectionConfidence.Unknown.ToString();
    public IReadOnlyList<EvidenceSignal> EvidenceSignals { get; init; } = Array.Empty<EvidenceSignal>();
    public required string ShortDescription { get; init; }
    public string Category { get; init; } = string.Empty;
    public int GroupedCount { get; init; } = 1;
    public IReadOnlyList<string> RepresentativeTargets { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> RiskDrivers { get; init; } = Array.Empty<string>();

    /// <summary>Stable fingerprint for matching this finding across audits.</summary>
    public string? Fingerprint { get; init; }
}
