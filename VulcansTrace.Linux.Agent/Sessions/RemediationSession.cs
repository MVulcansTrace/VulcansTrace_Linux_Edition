using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Sessions;

public sealed record RemediationSession
{
    public required string SessionId { get; init; }
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    public required IReadOnlyList<Finding> SourceFindings { get; init; }
    public required RemediationPlan RemediationPlan { get; init; }
    public required IReadOnlyDictionary<string, RemediationStepState> StepStates { get; init; }
    public AuditSnapshot? BeforeSnapshot { get; init; }
    public AuditSnapshot? AfterSnapshot { get; init; }
    public SessionVerificationResult? VerificationResult { get; init; }
    public RemediationSessionStatus Status { get; init; } = RemediationSessionStatus.Active;
    public required IReadOnlyList<string> BlockedReasons { get; init; } = Array.Empty<string>();
}

public enum RemediationSessionStatus
{
    Active,
    Blocked,
    Completed,
    Verified,
    Cancelled
}

public enum RemediationStepState
{
    Pending,
    InProgress,
    Completed,
    Skipped,
    Blocked,
    Failed
}

public sealed record AuditSnapshot
{
    public required IReadOnlyList<AuditSnapshotFinding> Findings { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required AgentIntent Intent { get; init; }
}

public sealed record SessionVerificationResult
{
    public required IReadOnlyList<AuditSnapshotFinding> FixedFindings { get; init; } = Array.Empty<AuditSnapshotFinding>();
    public required IReadOnlyList<AuditSnapshotFinding> UnchangedFindings { get; init; } = Array.Empty<AuditSnapshotFinding>();
    public required IReadOnlyList<AuditSnapshotFinding> NewFindings { get; init; } = Array.Empty<AuditSnapshotFinding>();
    public required IReadOnlyList<Reports.SeverityChangeFinding> WorsenedFindings { get; init; } = Array.Empty<Reports.SeverityChangeFinding>();
    public required string DiffNarrative { get; init; } = "";
    public DateTime VerifiedAtUtc { get; init; } = DateTime.UtcNow;
}
