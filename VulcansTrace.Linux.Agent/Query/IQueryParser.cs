namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Parses a natural language user query into a structured <see cref="AgentIntent"/>.
/// </summary>
public interface IQueryParser
{
    /// <summary>
    /// Analyzes the query text and returns the best-matching intent.
    /// </summary>
    /// <param name="query">The raw user query.</param>
    /// <returns>The inferred intent. Returns <see cref="AgentIntent.Help"/> when no confident match is found.</returns>
    AgentIntent Parse(string query);
}
