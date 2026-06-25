namespace VulcansTrace.Linux.Agent.Sessions;

public interface ISessionStore
{
    void Save(RemediationSession session);
    RemediationSession? Load(string sessionId);
    IReadOnlyList<RemediationSession> List();
    void Delete(string sessionId);

    /// <summary>Non-null when the persisted sessions could not be loaded or saved (e.g. a corrupt file was quarantined).</summary>
    string? PersistenceWarning { get; }
}
