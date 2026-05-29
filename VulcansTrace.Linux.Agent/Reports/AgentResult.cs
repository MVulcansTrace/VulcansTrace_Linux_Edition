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
}
