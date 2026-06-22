using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// A lightweight, persistable snapshot of the agent's conversation memory.
/// It intentionally does not duplicate full findings; it references the latest
/// <see cref="Reports.AuditHistoryEntry"/> by snapshot ID for rehydration.
/// </summary>
public sealed record AgentMemorySnapshot
{
    /// <summary>UTC timestamp when the snapshot was created.</summary>
    public DateTime UtcTimestamp { get; init; } = DateTime.UtcNow;

    /// <summary>The intent of the most recent turn.</summary>
    public AgentIntent LastIntent { get; init; } = AgentIntent.Help;

    /// <summary>The high-level topic of the most recent turn.</summary>
    public ConversationTopic LastTopic { get; init; } = ConversationTopic.Unknown;

    /// <summary>The intent of the most recent full audit.</summary>
    public AgentIntent LastAuditIntent { get; init; } = AgentIntent.FullAudit;

    /// <summary>The rule ID currently in focus, if any.</summary>
    public string? FocusedRuleId { get; init; }

    /// <summary>The category currently in focus, if any.</summary>
    public string? FocusedCategory { get; init; }

    /// <summary>The most recently created or resumed remediation session ID, if any.</summary>
    public string? LastRemediationSessionId { get; init; }

    /// <summary>The currently active remediation session ID, if any.</summary>
    public string? ActiveSessionId { get; init; }

    /// <summary>Snapshot ID of the latest audit history entry used to rehydrate the last result.</summary>
    public string? LatestAuditSnapshotId { get; init; }

    /// <summary>Recent conversation turns retained for continuity.</summary>
    public IReadOnlyList<DialogueTurn> RecentTurns { get; init; } = Array.Empty<DialogueTurn>();

    /// <summary>
    /// Per-rule audit history used to provide continuity ("this has been open for two weeks").
    /// Keys are rule IDs; values track severity history and remediation state.
    /// </summary>
    public IReadOnlyDictionary<string, RuleMemoryEntry> RuleHistory { get; init; } =
        new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Categories that have been audited, with the most recent timestamp for each.
    /// Used to surface long-horizon coverage blind spots.
    /// </summary>
    public IReadOnlyList<CategoryAuditEntry> CheckedCategories { get; init; } = Array.Empty<CategoryAuditEntry>();

    /// <summary>Current state of the diagnostic dialogue state machine.</summary>
    public DialogueState DiagnosticState { get; init; } = DialogueState.Idle;

    /// <summary>Rule ID under active diagnostic investigation, if any.</summary>
    public string? PendingDiagnosticRuleId { get; init; }

    /// <summary>The most recent diagnostic question asked by the agent, if any.</summary>
    public string? PendingDiagnosticQuestion { get; init; }
}
