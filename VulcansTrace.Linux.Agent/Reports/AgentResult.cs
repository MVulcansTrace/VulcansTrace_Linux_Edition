using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// The complete result of an agent audit operation.
/// Wraps findings from live system rules and optional log analysis.
/// </summary>
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
}
