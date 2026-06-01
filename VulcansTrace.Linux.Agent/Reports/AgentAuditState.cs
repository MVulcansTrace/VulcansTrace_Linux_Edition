using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class AgentAuditState
{
    private readonly object _historyLock = new();
    private readonly List<(string RuleId, Finding Finding)> _lastFindings = new();

    public AgentResult? LastResult { get; private set; }
    public AgentIntent LastAuditIntent { get; private set; } = AgentIntent.FullAudit;

    public void RememberAudit(AgentResult result, AgentIntent intent, IEnumerable<(string RuleId, Finding Finding)> findings)
    {
        ReplaceLastFindings(findings);
        LastResult = result;
        LastAuditIntent = intent;
    }

    public void RememberResult(AgentResult? result)
    {
        LastResult = result;
    }

    public void ReplaceLastFindings(IEnumerable<(string RuleId, Finding Finding)> findings)
    {
        lock (_historyLock)
        {
            _lastFindings.Clear();
            _lastFindings.AddRange(findings);
        }
    }

    public Finding? FindPreviousFinding(string reference)
    {
        lock (_historyLock)
        {
            foreach (var entry in _lastFindings)
            {
                if (entry.RuleId.Equals(reference, StringComparison.OrdinalIgnoreCase))
                    return entry.Finding;
            }

            return _lastFindings
                .Select(entry => entry.Finding)
                .FirstOrDefault(finding => MatchesReference(finding, reference));
        }
    }

    private static bool MatchesReference(Finding finding, string reference)
    {
        if (finding.ShortDescription.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Category.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Details.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        if (finding.Target.Contains(reference, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }
}
