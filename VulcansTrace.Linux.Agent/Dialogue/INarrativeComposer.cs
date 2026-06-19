using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Composes deterministic, traceable narrative prose from agent results,
/// posture correlations, and conversation memory.
/// </summary>
public interface INarrativeComposer
{
    /// <summary>
    /// Composes a narrative for the provided audit result.
    /// </summary>
    Narrative Compose(
        AgentResult result,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory,
        EntityFrame entities);
}
