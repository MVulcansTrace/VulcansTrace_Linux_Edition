using System;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Executes agent queries from the UI. The agent itself owns query parsing and
/// conversation context, so this executor only provides the selected-finding
/// shortcut for explanation queries.
/// </summary>
internal sealed class AgentQueryExecutor
{
    private readonly Func<IAgent> _getAgent;
    private readonly QueryParser _queryParser = new();

    public AgentQueryExecutor(Func<IAgent> getAgent)
    {
        _getAgent = getAgent ?? throw new ArgumentNullException(nameof(getAgent));
    }

    public Task<AgentResult> ExecuteAsync(
        string query,
        string? rawLog,
        Func<Finding?>? selectedFindingProvider,
        CancellationToken ct)
    {
        return ExecuteAsync(query, rawLog, selectedFindingProvider, null, ct);
    }

    public Task<AgentResult> ExecuteAsync(
        string query,
        string? rawLog,
        Func<Finding?>? selectedFindingProvider,
        IProgress<AgentAuditProgress>? progress,
        CancellationToken ct)
    {
        var agent = _getAgent();

        // Selected-finding shortcut: when the user has a finding selected in the UI
        // and asks to explain it without a reference, explain the selected finding
        // directly so the result is exactly the selected item and the dialogue context
        // is updated for follow-ups.
        var parsed = _queryParser.Parse(query);
        if (parsed.Intent == AgentIntent.ExplainFinding
            && string.IsNullOrWhiteSpace(parsed.TargetReference)
            && selectedFindingProvider != null)
        {
            var selected = selectedFindingProvider.Invoke();
            if (selected != null)
            {
                return agent.ExplainFindingAsync(selected, progress, ct);
            }
        }

        return agent.AskAsync(query, rawLog, progress, ct);
    }
}
