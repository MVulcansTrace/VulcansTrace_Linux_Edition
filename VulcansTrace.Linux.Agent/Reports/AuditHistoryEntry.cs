using VulcansTrace.Linux.Agent.Query;

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
}

/// <summary>
/// A lightweight snapshot of a single finding for history/diff purposes.
/// </summary>
public sealed record AuditSnapshotFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string Severity { get; init; }
    public required string ShortDescription { get; init; }
    public string Category { get; init; } = string.Empty;

    /// <summary>Stable fingerprint for matching this finding across audits.</summary>
    public string? Fingerprint { get; init; }
}
