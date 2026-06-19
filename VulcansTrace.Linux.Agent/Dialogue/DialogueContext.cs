using System.Collections.Immutable;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Multi-turn conversation context for the Security Agent.
/// Encapsulates the previous <see cref="AgentAuditState"/> capabilities
/// (last result, last audit intent, finding lookup) and adds dialogue history,
/// entity tracking, and ranked findings for anaphora resolution.
/// </summary>
public class DialogueContext
{
    private readonly object _lock = new();
    private readonly List<(string RuleId, Finding Finding)> _lastFindings = new();
    private readonly List<DialogueTurn> _history = new();

    /// <summary>Maximum number of turns retained in memory.</summary>
    public const int MaxHistoryTurns = 20;

    /// <summary>Maximum number of ranked findings tracked for ordinal resolution.</summary>
    public const int MaxRankedFindings = 100;

    /// <summary>The most recent agent result, if any.</summary>
    public AgentResult? LastResult { get; private set; }

    /// <summary>The intent of the most recent full audit.</summary>
    public AgentIntent LastAuditIntent { get; private set; } = AgentIntent.FullAudit;

    /// <summary>Immutable snapshot of the conversation history.</summary>
    public IReadOnlyList<DialogueTurn> History
    {
        get
        {
            lock (_lock)
            {
                return _history.ToImmutableList();
            }
        }
    }

    /// <summary>Currently tracked entities for anaphora and implicit intent resolution.</summary>
    public EntityFrame Entities { get; } = new();

    /// <summary>Records a full audit result and updates entity tracking.</summary>
    public void RememberAudit(AgentResult result, AgentIntent intent, IEnumerable<(string RuleId, Finding Finding)> findings)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(findings);

        lock (_lock)
        {
            _lastFindings.Clear();
            _lastFindings.AddRange(findings);
            LastResult = result;
            LastAuditIntent = intent;
            Entities.LastAuditIntent = intent;
            Entities.LastIntent = intent;
            Entities.LastTopic = TopicForIntent(intent);
            Entities.RankedFindings = RankFindings(result.AgentFindings);
            Entities.LastCategory = null;
            Entities.LastRuleId = null;
            Entities.LastFinding = null;
        }
    }

    /// <summary>Records a non-audit result (e.g., follow-up, explanation).</summary>
    public void RememberResult(AgentResult? result)
    {
        lock (_lock)
        {
            LastResult = result;

            if (result == null)
            {
                Entities.LastIntent = AgentIntent.Help;
                Entities.LastTopic = ConversationTopic.Unknown;
                return;
            }

            Entities.LastIntent = result.Intent;
            Entities.LastTopic = TopicForIntent(result.Intent);

            if (result.Intent is AgentIntent.StartRemediation
                or AgentIntent.VerifyRemediation
                or AgentIntent.ResumeRemediation
                && result.RemediationSession != null)
            {
                Entities.LastRemediationSession = result.RemediationSession;
                Entities.LastRemediationSessionId = result.RemediationSession.SessionId;
                Entities.ActiveSessionId = result.RemediationSession.SessionId;
            }

            if (result.AgentFindings.Count > 0)
            {
                Entities.RankedFindings = RankFindings(result.AgentFindings);
            }
        }
    }



    /// <summary>
    /// Returns a shallow copy of the current <see cref="Entities"/> frame under the internal lock.
    /// Resolve operations should read from the snapshot to avoid races with context updates.
    /// </summary>
    public EntityFrame SnapshotEntities()
    {
        lock (_lock)
        {
            return Entities.Clone();
        }
    }

    /// <summary>
    /// Captures the full dialogue state (last result + entity frame) for later restoration.
    /// Intended for save/restore patterns in follow-up services.
    /// </summary>
    public (AgentResult? LastResult, EntityFrame Entities) SnapshotState()
    {
        lock (_lock)
        {
            return (LastResult, Entities.Clone());
        }
    }

    /// <summary>
    /// Restores the full dialogue state captured by <see cref="SnapshotState"/>.
    /// </summary>
    public void RestoreState(AgentResult? lastResult, EntityFrame entities)
    {
        ArgumentNullException.ThrowIfNull(entities);

        lock (_lock)
        {
            LastResult = lastResult;
            var clone = entities.Clone();
            Entities.LastRuleId = clone.LastRuleId;
            Entities.LastFinding = clone.LastFinding;
            Entities.LastCategory = clone.LastCategory;
            Entities.ActiveSessionId = clone.ActiveSessionId;
            Entities.LastRemediationSessionId = clone.LastRemediationSessionId;
            Entities.RankedFindings = clone.RankedFindings;
            Entities.LastIntent = clone.LastIntent;
            Entities.LastTopic = clone.LastTopic;
            Entities.LastAuditIntent = clone.LastAuditIntent;
            Entities.LastRemediationSession = clone.LastRemediationSession;

            // Rebuild the rule-ID lookup table so explicit references like
            // "explain FW-001" work immediately after a restart.
            _lastFindings.Clear();
            if (lastResult != null)
            {
                _lastFindings.AddRange(lastResult.AgentFindings
                    .Select(f => (f.RuleId ?? string.Empty, f)));
            }
        }
    }

    /// <summary>Tracks that a specific finding/rule is now the focus of conversation.</summary>
    public void FocusFinding(Finding finding, string? ruleId = null)
    {
        ArgumentNullException.ThrowIfNull(finding);

        lock (_lock)
        {
            Entities.LastFinding = finding;
            Entities.LastRuleId = ruleId ?? finding.RuleId;
            Entities.LastCategory = finding.Category;
        }
    }

    /// <summary>Tracks that a specific category is now the focus of conversation.</summary>
    public void FocusCategory(string category)
    {
        lock (_lock)
        {
            Entities.LastCategory = category;
        }
    }

    /// <summary>Appends a resolved turn to the conversation history.</summary>
    public void PushTurn(DialogueTurn turn)
    {
        ArgumentNullException.ThrowIfNull(turn);

        lock (_lock)
        {
            _history.Add(turn);
            if (_history.Count > MaxHistoryTurns)
            {
                _history.RemoveAt(0);
            }
        }
    }

    /// <summary>
    /// Replaces the conversation history with the provided turns, respecting <see cref="MaxHistoryTurns"/>.
    /// </summary>
    /// <param name="turns">The turns to restore.</param>
    public void RestoreHistory(IReadOnlyList<DialogueTurn> turns)
    {
        ArgumentNullException.ThrowIfNull(turns);

        lock (_lock)
        {
            _history.Clear();
            _history.AddRange(turns.TakeLast(MaxHistoryTurns));
        }
    }

    /// <summary>Resets the entire conversation context.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _lastFindings.Clear();
            _history.Clear();
            LastResult = null;
            LastAuditIntent = AgentIntent.FullAudit;
            Entities.Clear();
        }
    }

    /// <summary>Looks up a previously seen finding by rule ID or text reference.</summary>
    public Finding? FindPreviousFinding(string reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
            return null;

        lock (_lock)
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

    /// <summary>Maps an intent to its high-level conversation topic.</summary>
    public static ConversationTopic TopicForIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.ExplainFinding or AgentIntent.ExplainCritical => ConversationTopic.Explanation,
        AgentIntent.FixFinding or AgentIntent.StartRemediation or AgentIntent.VerifyRemediation
            or AgentIntent.ListRemediationSessions or AgentIntent.ResumeRemediation
            or AgentIntent.AddSessionNote or AgentIntent.AddStepNote => ConversationTopic.Remediation,
        AgentIntent.ShowChanges or AgentIntent.CheckDrift or AgentIntent.ShowBaseline => ConversationTopic.Comparison,
        AgentIntent.SetBaseline => ConversationTopic.Drift,
        AgentIntent.Help => ConversationTopic.Help,
        _ => ConversationTopic.Audit
    };

    private static IReadOnlyList<Finding> RankFindings(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return Array.Empty<Finding>();

        // Rank by descending severity, then by category, then by rule ID for stable ordering.
        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .Take(MaxRankedFindings)
            .ToList();
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
