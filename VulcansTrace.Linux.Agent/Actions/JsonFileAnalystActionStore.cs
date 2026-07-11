using System.Text.Json;
using FluentValidation;
using VulcansTrace.Linux.Agent.Persistence;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Validation;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// An analyst action store that persists entries to a JSON file.
/// </summary>
public sealed class JsonFileAnalystActionStore : IAnalystActionStore, IDisposable
{
    private static readonly TimeSpan FileLockTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan FileLockRetryDelay = TimeSpan.FromMilliseconds(25);

    private readonly JsonFilePersistence<List<AnalystActionEntry>> _persistence;
    private readonly IValidator<AnalystActionEntry> _validator = new AnalystActionEntryValidator();
    private readonly string _lockPath;
    private readonly int _maxEntries;
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly List<AnalystActionEntry> _entries = new();
    private string? _persistenceWarning;
    private bool _hasSessionOnlyChanges;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFileAnalystActionStore"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 1000.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public JsonFileAnalystActionStore(string filePath, int maxEntries = 1000, ILogSink? logSink = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        // An audit log's whole purpose is durability: write to a temp file and rename it into place
        // so a crash/SIGKILL mid-write cannot truncate the live file and force a full quarantine.
        _persistence = new JsonFilePersistence<List<AnalystActionEntry>>(filePath, useAtomicWrite: true, logSink: logSink);
        _lockPath = filePath + ".lock";
        _maxEntries = maxEntries > 0 ? maxEntries : throw new ArgumentOutOfRangeException(nameof(maxEntries), "Must be greater than zero.");
        LoadFromDisk();
    }

    /// <summary>
    /// Creates a store in the user's config directory (XDG_CONFIG_HOME or ~/.config).
    /// </summary>
    /// <param name="configDirectory">Optional explicit base config directory.</param>
    /// <param name="maxEntries">Maximum number of entries to retain. Default is 1000.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics.</param>
    public static JsonFileAnalystActionStore CreateDefault(string? configDirectory = null, int maxEntries = 1000, ILogSink? logSink = null)
    {
        var dir = VulcansTraceConfig.GetDirectory(configDirectory);
        Directory.CreateDirectory(dir);
        return new JsonFileAnalystActionStore(Path.Combine(dir, "analyst-actions.json"), maxEntries, logSink);
    }

    /// <inheritdoc />
    public event EventHandler? Changed;

    /// <inheritdoc />
    public string? PersistenceWarning => ErrorSanitizer.SanitizeOptional(_persistenceWarning);

    /// <inheritdoc />
    public IReadOnlyList<AnalystActionEntry> GetAll()
    {
        _lock.EnterWriteLock();
        try
        {
            RefreshFromDiskForRead();
            return _entries.ToList();
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    /// <inheritdoc />
    public void Append(AnalystActionEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _lock.EnterWriteLock();
        try
        {
            CommitCandidate(diskEntries =>
            {
                var candidate = _hasSessionOnlyChanges
                    ? MergeEntries(diskEntries.Concat(_entries))
                    : diskEntries.ToList();
                candidate.Add(entry);
                return MergeEntries(candidate);
            });
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        OnChanged();
    }

    /// <inheritdoc />
    public void Clear()
    {
        _lock.EnterWriteLock();
        try
        {
            CommitCandidate(_ => new List<AnalystActionEntry>());
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        OnChanged();
    }

    /// <summary>Raises <see cref="Changed"/> off the write lock so subscribers can safely re-read.</summary>
    private void OnChanged() => Changed?.Invoke(this, EventArgs.Empty);

    private void Normalize(List<AnalystActionEntry> entries)
    {
        entries.Sort((a, b) => b.TimestampUtc.CompareTo(a.TimestampUtc));

        while (entries.Count > _maxEntries)
        {
            entries.RemoveAt(entries.Count - 1);
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            WithFileLock(() =>
            {
                var entries = LoadEntriesFromDisk();
                _entries.Clear();
                _entries.AddRange(entries);
                _hasSessionOnlyChanges = false;
            });
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load saved analyst actions (will retry next start): {ex.Message}";
            _entries.Clear();
            _hasSessionOnlyChanges = false;
        }
    }

    private void RefreshFromDiskForRead()
    {
        try
        {
            WithFileLock(() =>
            {
                var previousWarning = _persistenceWarning;
                var diskEntries = LoadEntriesFromDisk();
                var entries = _hasSessionOnlyChanges
                    ? MergeEntries(diskEntries.Concat(_entries))
                    : diskEntries;
                Normalize(entries);
                _entries.Clear();
                _entries.AddRange(entries);
                if (_persistenceWarning == null && !string.IsNullOrWhiteSpace(previousWarning))
                    _persistenceWarning = previousWarning;
            });
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not refresh analyst actions from disk: {ex.Message}";
        }
    }

    private List<AnalystActionEntry> LoadEntriesFromDisk()
    {
        try
        {
            var result = JsonStoreRecovery.LoadAndRepair(
                _persistence,
                _validator,
                "analyst action",
                a => a.ActionType);

            var entries = result.Valid;
            Normalize(entries);
            _persistenceWarning = result.Warning;
            return entries;
        }
        catch (Exception ex) when (ex is JsonException or ValidationException)
        {
            _persistence.Quarantine();
            _persistenceWarning = $"Could not load saved analyst actions; the file has been quarantined. {ex.Message}";
            return new List<AnalystActionEntry>();
        }
        catch (Exception ex)
        {
            _persistenceWarning = $"Could not load saved analyst actions (will retry next start): {ex.Message}";
            return new List<AnalystActionEntry>();
        }
    }

    private void CommitCandidate(Func<List<AnalystActionEntry>, List<AnalystActionEntry>> buildCandidate)
    {
        var committed = false;
        try
        {
            WithFileLock(() =>
            {
                var diskEntries = LoadEntriesFromDisk();
                var candidate = buildCandidate(diskEntries);
                Normalize(candidate);
                _validator.ValidateAllAndThrow(candidate);
                _entries.Clear();
                _entries.AddRange(candidate);

                committed = true;
                _persistence.Save(candidate);
                _persistenceWarning = null;
                _hasSessionOnlyChanges = false;
            });
        }
        catch (Exception ex)
        {
            if (!committed && ex is not ValidationException)
            {
                try
                {
                    var sessionCandidate = buildCandidate(_entries.ToList());
                    Normalize(sessionCandidate);
                    _validator.ValidateAllAndThrow(sessionCandidate);
                    _entries.Clear();
                    _entries.AddRange(sessionCandidate);
                    committed = true;
                }
                catch (ValidationException)
                {
                    // Keep invalid entries out of the live session view too.
                }
            }

            _persistenceWarning = committed
                ? $"Could not save analyst actions to disk: {ex.Message}. Actions will last only for this session."
                : $"Could not save analyst actions to disk: {ex.Message}. The attempted change was not saved.";
            _hasSessionOnlyChanges = committed;
        }
    }

    private static List<AnalystActionEntry> MergeEntries(IEnumerable<AnalystActionEntry> entries)
    {
        var byId = new Dictionary<string, AnalystActionEntry>(StringComparer.Ordinal);
        var invalidIdEntries = new List<AnalystActionEntry>();

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Id))
            {
                invalidIdEntries.Add(entry);
                continue;
            }

            if (!byId.TryGetValue(entry.Id, out var existing) || entry.TimestampUtc >= existing.TimestampUtc)
                byId[entry.Id] = entry;
        }

        var merged = byId.Values.ToList();
        merged.AddRange(invalidIdEntries);
        return merged;
    }

    private void WithFileLock(Action action)
    {
        using var fileLock = AcquireFileLock();
        action();
    }

    private FileStream AcquireFileLock()
    {
        var directory = Path.GetDirectoryName(_lockPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var deadline = DateTime.UtcNow.Add(FileLockTimeout);
        while (true)
        {
            try
            {
                return new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(FileLockRetryDelay);
            }
            catch (UnauthorizedAccessException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(FileLockRetryDelay);
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _lock.Dispose();
    }
}
