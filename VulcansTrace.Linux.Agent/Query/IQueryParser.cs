namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Parses a natural language user query into a structured <see cref="AgentQuery"/>.
/// </summary>
public interface IQueryParser
{
    /// <summary>
    /// Analyzes the query text and returns the best-matching intent and optional target reference.
    /// </summary>
    /// <param name="query">The raw user query.</param>
    /// <returns>The inferred intent and target reference. Returns <see cref="AgentIntent.Help"/> when no confident match is found.</returns>
    AgentQuery Parse(string query);
}
