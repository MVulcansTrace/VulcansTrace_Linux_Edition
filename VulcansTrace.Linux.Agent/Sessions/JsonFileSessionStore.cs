using System.Text.Json;

namespace VulcansTrace.Linux.Agent.Sessions;

public sealed class JsonFileSessionStore : ISessionStore, IDisposable
{
    private readonly string _filePath;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, RemediationSession> _sessions = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public JsonFileSessionStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        LoadFromDisk();
    }

    public static JsonFileSessionStore CreateDefault()
    {
        var configDir = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        var dir = Path.Combine(configDir, "VulcansTrace");
        Directory.CreateDirectory(dir);
        return new JsonFileSessionStore(Path.Combine(dir, "remediation-sessions.json"));
    }

    public void Save(RemediationSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _lock.EnterWriteLock();
        try
        {
            _sessions[session.SessionId] = session;
            PersistToDisk();
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
            _sessions.Remove(sessionId);
            PersistToDisk();
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
            if (!File.Exists(_filePath))
                return;

            var json = File.ReadAllText(_filePath);
            var sessions = JsonSerializer.Deserialize<List<RemediationSession>>(json, JsonOptions);
            if (sessions != null)
            {
                foreach (var session in sessions)
                {
                    _sessions[session.SessionId] = session;
                }
            }
        }
        catch
        {
            // Corrupted or unreadable file — start fresh
        }
    }

    private void PersistToDisk()
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath);
            if (dir != null)
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(_sessions.Values.ToList(), JsonOptions);
            File.WriteAllText(_filePath, json);
        }
        catch
        {
            // Persistence failure — data is still in memory
        }
    }

    public void Dispose()
    {
        _lock.Dispose();
    }
}
