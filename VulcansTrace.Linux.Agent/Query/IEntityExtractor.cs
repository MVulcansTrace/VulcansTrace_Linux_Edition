namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Extracts structured entities from a raw user query.
/// </summary>
public interface IEntityExtractor
{
    /// <summary>
    /// Extracts entities from the provided raw query.
    /// </summary>
    /// <param name="query">The raw user query.</param>
    /// <returns>A populated <see cref="QueryEntityFrame"/>.</returns>
    QueryEntityFrame Extract(string query);
}
