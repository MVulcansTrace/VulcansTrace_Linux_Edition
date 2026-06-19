namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// A non-durable memory store that keeps the latest snapshot in memory.
/// Useful as a fallback when filesystem persistence is unavailable.
/// </summary>
public sealed class InMemoryAgentMemoryStore : IAgentMemoryStore
{
    private AgentMemorySnapshot? _snapshot;

    /// <summary>
    /// Initializes a new in-memory memory store.
    /// </summary>
    /// <param name="persistenceWarning">Optional warning explaining why persistence is unavailable.</param>
    public InMemoryAgentMemoryStore(string? persistenceWarning = null)
    {
        PersistenceWarning = persistenceWarning;
    }

    /// <inheritdoc />
    public string? PersistenceWarning { get; }

    /// <inheritdoc />
    public AgentMemorySnapshot? Load()
    {
        return _snapshot;
    }

    /// <inheritdoc />
    public Task SaveAsync(AgentMemorySnapshot snapshot)
    {
        _snapshot = snapshot;
        return Task.CompletedTask;
    }
}
