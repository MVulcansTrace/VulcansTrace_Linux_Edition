namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Diagnostic dialogue state for recurring-finding investigations.
/// State lives on <see cref="EntityFrame"/> so it survives snapshot/restore.
/// </summary>
public enum DialogueState
{
    /// <summary>No active diagnostic dialogue.</summary>
    Idle,

    /// <summary>A recurrence investigation has been initiated.</summary>
    Investigating,

    /// <summary>The agent has asked a diagnostic question and is waiting for the user's answer.</summary>
    AwaitingDiagnosticAnswer,

    /// <summary>The agent has proposed a root cause and is waiting for user acknowledgment or topic change.</summary>
    RootCauseProposed
}
