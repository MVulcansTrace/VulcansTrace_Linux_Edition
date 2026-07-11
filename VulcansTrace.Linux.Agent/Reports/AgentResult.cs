using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Agent.Reports;

public sealed record AgentResult
{
    /// <summary>Findings produced by agent security rules.</summary>
    public IReadOnlyList<Finding> AgentFindings { get; init; } = Array.Empty<Finding>();

    /// <summary>Optional log analysis result (null when no log was provided).</summary>
    public AnalysisResult? LogAnalysisResult { get; init; }

    /// <summary>Warnings collected during scanning or analysis.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    /// <summary>Timestamp when the audit completed.</summary>
    public DateTime UtcTimestamp { get; init; } = DateTime.UtcNow;

    /// <summary>User-facing summary text.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>Hint for chat renderers to trim output. Render-only: does not alter findings, LastResult, or history.</summary>
    public ResponseVerbosity Verbosity { get; init; } = ResponseVerbosity.Normal;

    /// <summary>The intent that triggered this audit.</summary>
    public Query.AgentIntent Intent { get; init; }

    /// <summary>All rule results from the audit, including passes and failures.</summary>
    public IReadOnlyList<Rules.RuleResult> RuleResults { get; init; } = Array.Empty<Rules.RuleResult>();

    /// <summary>Number of rules that passed.</summary>
    public int PassedCount { get; init; }

    /// <summary>Number of rules that failed (findings before suppression).</summary>
    public int FailedCount { get; init; }

    /// <summary>Number of findings suppressed by user configuration.</summary>
    public int SuppressedCount { get; init; }

    /// <summary>Number of rules that crashed during evaluation.</summary>
    public int CrashedCount { get; init; }

    /// <summary>Human-readable report of which data sources were available during the audit.</summary>
    public string CapabilityReport { get; init; } = string.Empty;

    /// <summary>
    /// Structured data-source capabilities from the audit, used by follow-up intents
    /// such as <see cref="Query.AgentIntent.ShowEvidence"/> for provenance reporting.
    /// </summary>
    public IReadOnlyList<DataSourceCapability> DataSourceCapabilities { get; init; } = Array.Empty<DataSourceCapability>();

    /// <summary>Diff against a prior audit, populated for <see cref="Query.AgentIntent.ShowChanges"/>.</summary>
    public AuditDiff? AuditDiff { get; init; }

    /// <summary>Remediation plan from the last result, populated for <see cref="Query.AgentIntent.PrioritizeRemediation"/>.</summary>
    public RemediationPlan? RemediationPlan { get; init; }

    /// <summary>Drift result against a saved baseline, populated for <see cref="Query.AgentIntent.CheckDrift"/>.</summary>
    public Baselines.BaselineDiffResult? BaselineDiff { get; init; }

    /// <summary>The active baseline, populated for <see cref="Query.AgentIntent.ShowBaseline"/>.</summary>
    public Baselines.BaselineEntry? Baseline { get; init; }

    /// <summary>CIS compliance scorecard with pass/fail/warn per control family and trend.</summary>
    public Core.Compliance.ComplianceScorecard? Scorecard { get; init; }

    /// <summary>Risk scorecard aggregating findings into a graded numeric score.</summary>
    public Core.RiskScorecard? RiskScorecard { get; init; }

    /// <summary>Remediation session, populated for StartRemediation and VerifyRemediation intents.</summary>
    public RemediationSession? RemediationSession { get; init; }

    /// <summary>Persisted remediation sessions, populated for ListRemediationSessions intent.</summary>
    public IReadOnlyList<RemediationSession> RemediationSessions { get; init; } = Array.Empty<RemediationSession>();

    /// <summary>Contextual follow-up suggestions generated for this result.</summary>
    public IReadOnlyList<SuggestedFollowUp> Suggestions { get; init; } = Array.Empty<SuggestedFollowUp>();

    /// <summary>Audit-history snapshot ID for this result, when persisted.</summary>
    public string? SnapshotId { get; init; }

    /// <summary>
    /// Cross-category posture correlations detected for this audit.
    /// These do not create new findings; they annotate combinations of existing findings.
    /// </summary>
    public IReadOnlyList<PostureCorrelation> PostureCorrelations { get; init; } = Array.Empty<PostureCorrelation>();

    /// <summary>
    /// A composed narrative summary for the result, if generated.
    /// </summary>
    public Dialogue.Narrative? Narrative { get; init; }

    /// <summary>
    /// System-level trajectory derived from per-rule trend history.
    /// </summary>
    public SystemTrajectory? SystemTrajectory { get; init; }

    /// <summary>
    /// Findings that have returned after a previous verified fix, surfaced proactively.
    /// </summary>
    public IReadOnlyList<ProactiveAlert> ProactiveAlerts { get; init; } = Array.Empty<ProactiveAlert>();

    /// <summary>
    /// Deterministic attack chains built from posture-backed finding relationships.
    /// </summary>
    public IReadOnlyList<AttackChain> AttackChains { get; init; } = Array.Empty<AttackChain>();

    /// <summary>
    /// Remediation wisdom for rules with repeated fix-and-return cycles.
    /// </summary>
    public IReadOnlyList<RemediationWisdom> RemediationWisdom { get; init; } = Array.Empty<RemediationWisdom>();
}
