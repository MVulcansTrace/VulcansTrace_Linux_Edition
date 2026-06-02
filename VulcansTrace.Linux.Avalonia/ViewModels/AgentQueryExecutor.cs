using System;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

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
        var agent = _getAgent();
        var parsed = _queryParser.Parse(query);

        if (parsed.Intent == AgentIntent.ExplainFinding && string.IsNullOrWhiteSpace(parsed.TargetReference))
        {
            var selected = selectedFindingProvider?.Invoke();
            if (selected != null)
            {
                return agent.ExplainFindingAsync(selected, ct);
            }
        }

        return agent.AskAsync(query, rawLog, ct);
    }
}
