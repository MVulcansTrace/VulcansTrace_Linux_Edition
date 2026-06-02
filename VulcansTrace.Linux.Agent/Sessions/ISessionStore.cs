namespace VulcansTrace.Linux.Agent.Sessions;

public interface ISessionStore
{
    void Save(RemediationSession session);
    RemediationSession? Load(string sessionId);
    IReadOnlyList<RemediationSession> List();
    void Delete(string sessionId);
}
