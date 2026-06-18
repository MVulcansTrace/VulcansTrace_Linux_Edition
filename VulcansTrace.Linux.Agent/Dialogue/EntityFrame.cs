using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Tracks the entities currently under discussion in the conversation.
/// These values are used to resolve anaphora and implicit references.
/// </summary>
public sealed class EntityFrame
{
    /// <summary>The rule ID last discussed (e.g., "FW-001").</summary>
    public string? LastRuleId { get; set; }

    /// <summary>The finding last explained or selected.</summary>
    public Finding? LastFinding { get; set; }

    /// <summary>The category last discussed (e.g., "SSH", "Container").</summary>
    public string? LastCategory { get; set; }

    /// <summary>The active remediation session ID, if any.</summary>
    public string? ActiveSessionId { get; set; }

    /// <summary>The most recently created or resumed remediation session ID.</summary>
    public string? LastRemediationSessionId { get; set; }

    /// <summary>
    /// Findings from the last response, ordered for ordinal reference resolution
    /// (e.g., "explain the third one").
    /// </summary>
    public IReadOnlyList<Finding> RankedFindings { get; set; } = Array.Empty<Finding>();

    /// <summary>The intent of the last turn.</summary>
    public AgentIntent LastIntent { get; set; } = AgentIntent.Help;

    /// <summary>The topic of the last turn.</summary>
    public ConversationTopic LastTopic { get; set; } = ConversationTopic.Unknown;

    /// <summary>The last audit intent that was run (distinct from follow-up intents).</summary>
    public AgentIntent LastAuditIntent { get; set; } = AgentIntent.FullAudit;

    /// <summary>The last remediation session object, when loaded or created.</summary>
    public RemediationSession? LastRemediationSession { get; set; }

    /// <summary>Creates a shallow copy of the current entity frame.</summary>
    public EntityFrame Clone()
    {
        return new EntityFrame
        {
            LastRuleId = LastRuleId,
            LastFinding = LastFinding,
            LastCategory = LastCategory,
            ActiveSessionId = ActiveSessionId,
            LastRemediationSessionId = LastRemediationSessionId,
            RankedFindings = RankedFindings,
            LastIntent = LastIntent,
            LastTopic = LastTopic,
            LastAuditIntent = LastAuditIntent,
            LastRemediationSession = LastRemediationSession
        };
    }

    /// <summary>Clears all tracked entities.</summary>
    public void Clear()
    {
        LastRuleId = null;
        LastFinding = null;
        LastCategory = null;
        ActiveSessionId = null;
        LastRemediationSessionId = null;
        LastRemediationSession = null;
        RankedFindings = Array.Empty<Finding>();
        LastIntent = AgentIntent.Help;
        LastTopic = ConversationTopic.Unknown;
        LastAuditIntent = AgentIntent.FullAudit;
    }
}
