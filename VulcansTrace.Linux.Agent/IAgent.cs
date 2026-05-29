using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;

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
}
