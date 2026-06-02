using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent;

/// <summary>
/// The main agent interface for answering security queries and running audits.
/// </summary>
public interface IAgent
{
    /// <summary>
    /// Answers a natural language user query by parsing intent, running the appropriate audit, and returning results.
    /// </summary>
    /// <param name="query">The user's natural language query.</param>
    /// <param name="rawLog">Optional firewall log content to include in the analysis.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent audit result.</returns>
    Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct);

    /// <summary>
    /// Runs a targeted audit for the specified intent.
    /// </summary>
    /// <param name="intent">The structured intent to execute.</param>
    /// <param name="rawLog">Optional firewall log content to include in the analysis.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent audit result.</returns>
    Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct);

    /// <summary>
    /// Returns a focused explanation for the provided finding without re-running scans or rules.
    /// </summary>
    /// <param name="finding">The finding to explain.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>An agent result containing only the explained finding.</returns>
    Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct);

    /// <summary>
    /// Saves the most recent audit result as a known-good baseline.
    /// </summary>
    /// <param name="name">User-friendly name for the baseline.</param>
    /// <param name="description">Optional description.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result confirming the baseline was saved.</returns>
    Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct);

    /// <summary>
    /// Runs an audit and compares it against the active baseline for the intent.
    /// </summary>
    /// <param name="intent">The audit intent to check.</param>
    /// <param name="rawLog">Optional firewall log content.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result with drift findings.</returns>
    Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct);

    /// <summary>
    /// Returns the active baseline for the specified intent without running an audit.
    /// </summary>
    /// <param name="intent">The audit intent.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the baseline findings.</returns>
    Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct);

    /// <summary>
    /// Starts a guided remediation session for the specified finding reference.
    /// </summary>
    /// <param name="findingReference">The finding ID or reference to remediate (e.g. "FW-001").</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the remediation session.</returns>
    Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct);

    /// <summary>
    /// Runs verification on an active remediation session, re-auditing and producing a before/after diff.
    /// </summary>
    /// <param name="sessionId">The session ID to verify.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the verification diff.</returns>
    Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct);

    /// <summary>
    /// Records that a remediation session was exported by appending an Exported timeline event.
    /// </summary>
    /// <param name="sessionId">The session ID that was exported.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the updated session.</returns>
    Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct);

    /// <summary>
    /// Lists all persisted remediation sessions.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the list of sessions.</returns>
    Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct);

    /// <summary>
    /// Loads a previously persisted remediation session by ID.
    /// </summary>
    /// <param name="sessionId">The session ID to load.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result containing the session, or a not-found message.</returns>
    Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct);

    /// <summary>
    /// Deletes a persisted remediation session by ID.
    /// </summary>
    /// <param name="sessionId">The session ID to delete.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The agent result confirming deletion or explaining why it could not be deleted.</returns>
    Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct);
}
