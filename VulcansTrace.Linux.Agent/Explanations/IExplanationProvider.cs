namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Provides human-readable explanations for rule results by loading and filling templates.
/// </summary>
public interface IExplanationProvider
{
    /// <summary>
    /// Retrieves the explanation text for the given template key, substituting variables.
    /// </summary>
    /// <param name="key">Template key (e.g., "FW-001").</param>
    /// <param name="variables">Key-value pairs to replace in the template.</param>
    /// <returns>The formatted explanation text. Returns a fallback message if the key is unknown.</returns>
    string GetExplanation(string key, IReadOnlyDictionary<string, string> variables);
}
