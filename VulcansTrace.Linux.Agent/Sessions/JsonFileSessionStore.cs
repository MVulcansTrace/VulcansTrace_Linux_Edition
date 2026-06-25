using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Sessions;

public sealed class JsonFileSessionStore : ISessionStore, IDisposable
{
    private readonly JsonFilePersistence<List<RemediationSession>> _persistence;
    private readonly IValidator<RemediationSession> _validator = new RemediationSessionValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, RemediationSession> _sessions = new();
    private string? _persistenceWarning;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new UtcDateTimeJsonConverter() }
    };

    public JsonFileSessionStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<RemediationSession>>(filePath, JsonOptions, logSink: logSink);
        LoadFromDisk();
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _persistenceWarning;

    public static JsonFileSessionStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileSessionStore(Path.Combine(dir, "remediation-sessions.json"), logSink);
    }

    public void Save(RemediationSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, RemediationSession>(_sessions, StringComparer.Ordinal)
            {
                [session.SessionId] = session
            };
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public RemediationSession? Load(string sessionId)
    {
        _lock.EnterReadLock();
        try
        {
            return _sessions.TryGetValue(sessionId, out var session) ? session : null;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public IReadOnlyList<RemediationSession> List()
    {
        _lock.EnterReadLock();
        try
        {
            return _sessions.Values.OrderByDescending(s => s.CreatedAtUtc).ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public void Delete(string sessionId)
    {
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, RemediationSession>(_sessions, StringComparer.Ordinal);
            candidate.Remove(sessionId);
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var sessions = _persistence.Load();
            if (sessions != null)
            {
                _validator.ValidateAllAndThrow(sessions);
                foreach (var session in sessions)
                {
                    _sessions[session.SessionId] = session;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            // Corrupt or semantically invalid JSON — move it aside so we don't retry a known-bad file.
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved remediation sessions; the file has been quarantined. {ex.Message}";
            _sessions.Clear();
        }
        catch (Exception ex)
        {
            // Transient failure (e.g. I/O or sharing violation) — leave the file in place to retry next start.
            _persistenceWarning = $"Could not load saved remediation sessions (will retry next start): {ex.Message}";
            _sessions.Clear();
        }
    }

    private void CommitCandidate(Dictionary<string, RemediationSession> candidate)
    {
        var committed = false;
        try
        {
            var snapshot = candidate.Values.ToList();
            _validator.ValidateAllAndThrow(snapshot);

            _sessions.Clear();
            foreach (var session in snapshot)
            {
                _sessions[session.SessionId] = session;
            }

            committed = true;
            _persistence.Save(snapshot);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            // Persistence failure — data survives in memory for this session only.
            _persistenceWarning = committed
                ? $"Could not save remediation sessions to disk: {ex.Message}. Sessions will last only for this session."
                : $"Could not save remediation sessions to disk: {ex.Message}. Invalid sessions were not saved.";
        }
    }

    public void Dispose()
    {
        _lock.Dispose();
    }
}
