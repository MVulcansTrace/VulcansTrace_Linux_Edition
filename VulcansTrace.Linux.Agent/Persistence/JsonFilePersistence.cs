using System.Text.Json;
using System.Threading;
using System.Runtime.Versioning;
using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Persistence;

/// <summary>
/// Low-level mechanical helper for loading and saving a typed snapshot from/to a JSON file.
/// This class owns only file I/O and serialization; callers retain business logic, locking,
/// and error handling (e.g., <c>PersistenceWarning</c>).
/// </summary>
/// <typeparam name="T">The type serialized to and from the JSON file.</typeparam>
internal sealed class JsonFilePersistence<T>
{
    private readonly string _filePath;
    private readonly JsonSerializerOptions _options;
    private readonly bool _useAtomicWrite;
    private readonly UnixFileMode? _unixFileMode;
    private readonly ILogSink? _logSink;

    /// <summary>
    /// Initializes a new instance of the <see cref="JsonFilePersistence{T}"/> class.
    /// </summary>
    /// <param name="filePath">The full path to the JSON file.</param>
    /// <param name="options">Serialization options. Defaults to <see cref="JsonOptionsProvider.Default"/>.</param>
    /// <param name="useAtomicWrite">If true, writes to a temp file and moves it into place.</param>
    /// <param name="unixFileMode">Optional Unix file mode to enforce for files containing sensitive data.</param>
    /// <param name="logSink">Optional log sink for persistence diagnostics such as quarantine failures.</param>
    public JsonFilePersistence(
        string filePath,
        JsonSerializerOptions? options = null,
        bool useAtomicWrite = false,
        UnixFileMode? unixFileMode = null,
        ILogSink? logSink = null)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _options = options ?? JsonOptionsProvider.Default;
        _useAtomicWrite = useAtomicWrite;
        _unixFileMode = unixFileMode;
        _logSink = logSink;
    }

    /// <summary>
    /// Reads and deserializes the file. Returns <c>default</c> if the file does not exist.
    /// </summary>
    /// <returns>The deserialized snapshot, or <c>default</c> if the file is missing.</returns>
    public T? Load()
    {
        if (!File.Exists(_filePath))
            return default;

        var json = File.ReadAllText(_filePath);
        return JsonSerializer.Deserialize<T>(json, _options);
    }

    /// <summary>
    /// Serializes and writes the snapshot to disk, creating the directory if necessary.
    /// </summary>
    /// <param name="value">The value to persist.</param>
    public void Save(T value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(value, _options);
        WriteAllText(json);
    }

    /// <summary>
    /// Asynchronously serializes and writes the snapshot to disk, creating the directory if necessary.
    /// </summary>
    /// <param name="value">The value to persist.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task SaveAsync(T value, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(value);

        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(value, _options);
        await WriteAllTextAsync(json, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Moves the persisted file to a quarantine location so a corrupt or invalid file is not
    /// loaded again on the next process start. Safe to call even if the file does not exist.
    /// </summary>
    /// <returns>The full path of the quarantined file, or <c>null</c> if no file existed or the move failed.</returns>
    public string? Quarantine()
    {
        try
        {
            if (!File.Exists(_filePath))
                return null;

            var quarantinePath = GetUniqueQuarantinePath();
            File.Move(_filePath, quarantinePath);
            return quarantinePath;
        }
        catch (Exception ex)
        {
            // Quarantine is best-effort: never throw over a load failure. Surface the move
            // failure through the configured log sink so a corrupt file that could not be
            // set aside is not silently retried.
            _logSink?.Write(LogLevel.Error, $"Failed to quarantine corrupt persistence file '{_filePath}': {ex.Message}", ex);
            return null;
        }
    }

    private string GetUniqueQuarantinePath()
    {
        var directory = Path.GetDirectoryName(_filePath);
        var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(_filePath);
        var extension = Path.GetExtension(_filePath);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
        var basePath = Path.Combine(directory ?? string.Empty, $"{fileNameWithoutExtension}.corrupt.{timestamp}{extension}");

        if (!File.Exists(basePath))
            return basePath;

        for (var counter = 1; counter < 1000; counter++)
        {
            var candidate = Path.Combine(directory ?? string.Empty, $"{fileNameWithoutExtension}.corrupt.{timestamp}_{counter}{extension}");
            if (!File.Exists(candidate))
                return candidate;
        }

        // Fallback to a GUID suffix if all counters are exhausted (extremely unlikely).
        return Path.Combine(directory ?? string.Empty, $"{fileNameWithoutExtension}.corrupt.{timestamp}.{Guid.NewGuid()}{extension}");
    }

    private void WriteAllText(string json)
    {
        if (_useAtomicWrite)
        {
            var tempPath = _filePath + ".tmp";
            WriteFile(tempPath, json);
            File.Move(tempPath, _filePath, overwrite: true);
            ApplyUnixFileMode(_filePath);
        }
        else
        {
            WriteFile(_filePath, json);
        }
    }

    private async Task WriteAllTextAsync(string json, CancellationToken cancellationToken)
    {
        if (_useAtomicWrite)
        {
            var tempPath = _filePath + ".tmp";
            await WriteFileAsync(tempPath, json, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, _filePath, overwrite: true);
            ApplyUnixFileMode(_filePath);
        }
        else
        {
            await WriteFileAsync(_filePath, json, cancellationToken).ConfigureAwait(false);
        }
    }

    private void WriteFile(string path, string json)
    {
        if (_unixFileMode is not { } unixFileMode || OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, json);
            return;
        }

        ApplyUnixFileMode(path);
        var options = CreateSecureFileStreamOptions(unixFileMode);
        using var stream = new FileStream(path, options);
        using var writer = new StreamWriter(stream);
        writer.Write(json);
        ApplyUnixFileMode(path);
    }

    private async Task WriteFileAsync(string path, string json, CancellationToken cancellationToken)
    {
        if (_unixFileMode is not { } unixFileMode || OperatingSystem.IsWindows())
        {
            await File.WriteAllTextAsync(path, json, cancellationToken).ConfigureAwait(false);
            return;
        }

        ApplyUnixFileMode(path);
        var options = CreateSecureFileStreamOptions(unixFileMode);
        await using var stream = new FileStream(path, options);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
        ApplyUnixFileMode(path);
    }

    [UnsupportedOSPlatform("windows")]
    private static FileStreamOptions CreateSecureFileStreamOptions(UnixFileMode unixFileMode)
        => new()
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = unixFileMode
        };

    private void ApplyUnixFileMode(string path)
    {
        if (_unixFileMode is not { } unixFileMode || OperatingSystem.IsWindows() || !File.Exists(path))
            return;

        File.SetUnixFileMode(path, unixFileMode);
    }
}
