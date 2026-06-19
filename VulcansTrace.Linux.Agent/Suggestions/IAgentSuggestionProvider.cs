using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Suggestions;

/// <summary>
/// Generates contextual follow-up suggestions for an agent result.
/// </summary>
public interface IAgentSuggestionProvider
{
    /// <summary>
    /// Returns suggested follow-up queries based on the current result and conversation context.
    /// </summary>
    /// <param name="result">The result just produced by the agent.</param>
    /// <param name="entities">The current entity frame from the dialogue context.</param>
    /// <returns>An ordered list of follow-up suggestions.</returns>
    IReadOnlyList<SuggestedFollowUp> GetSuggestions(AgentResult result, EntityFrame entities);
}
