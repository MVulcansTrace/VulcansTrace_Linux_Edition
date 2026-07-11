using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Messages;

/// <summary>
/// A pinned-message store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFilePinnedMessageStore : IPinnedMessageStore, IDisposable
{
    private readonly JsonFilePersistence<List<PinnedMessage>> _persistence;
    private readonly IValidator<PinnedMessage> _validator = new PinnedMessageValidator();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly Dictionary<string, PinnedMessage> _entries = new(StringComparer.OrdinalIgnoreCase);
    private string? _persistenceWarning;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFilePinnedMessageStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFilePinnedMessageStore(string filePath, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        _persistence = new JsonFilePersistence<List<PinnedMessage>>(filePath, JsonOptions, logSink: logSink);
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    /// <returns>A configured <see cref="JsonFilePinnedMessageStore"/>.</returns>
    public static JsonFilePinnedMessageStore CreateDefault(string? configDirectory = null, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFilePinnedMessageStore(Path.Combine(dir, "pinned-messages.json"), logSink);
    }

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

    /// <inheritdoc />
    public void Pin(PinnedMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, PinnedMessage>(_entries, StringComparer.OrdinalIgnoreCase)
            {
                [message.MessageId] = message
            };
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Unpin(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        _lock.EnterWriteLock();
        try
        {
            var candidate = new Dictionary<string, PinnedMessage>(_entries, StringComparer.OrdinalIgnoreCase);
            candidate.Remove(messageId);
            CommitCandidate(candidate);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public bool IsPinned(string messageId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        _lock.EnterReadLock();
        try
        {
            return _entries.ContainsKey(messageId);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<PinnedMessage> GetAll()
    {
        _lock.EnterReadLock();
        try
        {
            return _entries.Values
                .OrderByDescending(m => m.PinnedAtUtc)
                .ToList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "pinned message",
                m => m.MessageId);

            _entries.Clear();
            foreach (var message in result.Valid)
            {
                _entries[message.MessageId] = message;
            }

            _persistenceWarning = result.Warning;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved pinned messages; the file has been quarantined. {ex.Message}";
            _entries.Clear();
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load saved pinned messages (will retry next start): {ex.Message}";
            _entries.Clear();
        }
    }

    private void CommitCandidate(Dictionary<string, PinnedMessage> candidate)
    {
        var committed = false;
        try
        {
            var snapshot = candidate.Values.ToList();
            _validator.ValidateAllAndThrow(snapshot);

            _entries.Clear();
            foreach (var message in snapshot)
            {
                _entries[message.MessageId] = message;
            }

            committed = true;
            _persistence.Save(snapshot);
            _persistenceWarning = null;
        }
        catch (Exception ex)
        {
            _persistenceWarning = committed
                ? $"Could not save pinned messages to disk: {ex.Message}. Pins will last only for this session."
                : $"Could not save pinned messages to disk: {ex.Message}. Invalid pins were not saved.";
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
