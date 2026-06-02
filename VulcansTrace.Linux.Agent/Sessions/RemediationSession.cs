using System.Collections.Immutable;
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
    private readonly IReadOnlyList<string> _blockedReasons = Array.Empty<string>();

    public IReadOnlyList<string> BlockedReasons
    {
        get => _blockedReasons;
        init => _blockedReasons = value ?? Array.Empty<string>();
    }

    private readonly ImmutableList<RemediationSessionEvent> _timeline = ImmutableList<RemediationSessionEvent>.Empty;

    public IReadOnlyList<RemediationSessionEvent> Timeline
    {
        get => _timeline;
        init => _timeline = value is ImmutableList<RemediationSessionEvent> immutable
            ? immutable
            : ImmutableList.CreateRange(value ?? Array.Empty<RemediationSessionEvent>());
    }
}

public enum RemediationSessionStatus
{
    Active,
    Blocked,
    Completed,
    Verified
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

public enum RemediationSessionEventType
{
    Created,
    StepMarkedPending,
    StepMarkedInProgress,
    StepMarkedCompleted,
    StepMarkedSkipped,
    StepMarkedFailed,
    StepBlocked,
    VerificationStarted,
    VerificationCompleted,
    VerificationBlocked,
    VerificationFailed,
    Exported
}

public sealed record RemediationSessionEvent
{
    public required DateTime TimestampUtc { get; init; }
    public required RemediationSessionEventType Type { get; init; }
    public required string Title { get; init; }
    public string Details { get; init; } = "";
    public string? RuleId { get; init; }
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
