namespace VulcansTrace.Linux.Agent.Sessions;

public sealed class InMemorySessionStore : ISessionStore
{
    private readonly Dictionary<string, RemediationSession> _sessions = new();
    private readonly string? _warning;

    public InMemorySessionStore(string? warning = null)
    {
        _warning = warning;
    }

    public string? PersistenceWarning => _sessions.Count > 0 ? _warning : null;

    public void Save(RemediationSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _sessions[session.SessionId] = session;
    }

    public RemediationSession? Load(string sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) ? session : null;
    }

    public IReadOnlyList<RemediationSession> List()
    {
        return _sessions.Values.OrderByDescending(s => s.CreatedAtUtc).ToList();
    }

    public void Delete(string sessionId)
    {
        _sessions.Remove(sessionId);
    }
}
