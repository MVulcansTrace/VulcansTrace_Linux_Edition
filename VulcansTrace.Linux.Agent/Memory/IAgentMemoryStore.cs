namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Defines storage and retrieval of the agent's lightweight conversation memory snapshot.
/// </summary>
public interface IAgentMemoryStore
{
    /// <summary>
    /// Loads the most recently saved memory snapshot, or null if none exists.
    /// </summary>
    AgentMemorySnapshot? Load();

    /// <summary>
    /// Persists the given memory snapshot asynchronously.
    /// </summary>
    /// <param name="snapshot">The snapshot to save.</param>
    Task SaveAsync(AgentMemorySnapshot snapshot);

    /// <summary>
    /// Gets the latest persistence warning, if memory could not be stored durably.
    /// </summary>
    string? PersistenceWarning { get; }
}
