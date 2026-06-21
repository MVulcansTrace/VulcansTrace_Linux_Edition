using System.Text;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Scans live process runtime state from /proc/&lt;pid&gt;/ for DFIR indicators:
/// memory maps, environment variables, executable paths, command lines, and parent-child relationships.
///
/// Design notes:
/// • Bounded concurrency (SemaphoreSlim) to avoid fork-bombing readlink and procfs contention.
/// • Each /proc file is read in its own try block so EACCES on one file does not drop the whole process.
/// • cmdline and environ are read with read loops into bounded MemoryStream to handle partial procfs reads.
/// • Cancellation is re-thrown so the orchestrator can distinguish cancel from empty /proc.
/// • No PID count cap — all processes are scanned. Memory is bounded per-process via buffer limits.
/// • Thread-level inspection (/proc/&lt;pid&gt;/task/*) is not performed; injection into individual threads
///   of a multi-threaded process would not surface distinct maps here.
/// </summary>
public sealed class ProcessRuntimeScanner : IScanner
{
    private const int MaxConcurrency = 50;
    private const int MaxCmdlineBytes = 65_536;
    private const int MaxEnvironBytes = 262_144;
    private const int MaxMapsBytes = 524_288;

    /// <inheritdoc />
    public string Name => "ProcessRuntime";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        bool anyReadable = false;
        int processedCount = 0;
        int cmdlineUnreadableCount = 0;
        int mapsUnreadableCount = 0;
        int environUnreadableCount = 0;
        int exeUnreadableCount = 0;

        try
        {
            var procEntries = Directory.GetDirectories("/proc")
                .Select(Path.GetFileName)
                .Where(name => name != null && name.All(char.IsDigit))
                .Select(name => int.Parse(name!))
                .ToList();

            using var semaphore = new SemaphoreSlim(MaxConcurrency, MaxConcurrency);
            var tasks = new List<Task<ProcessRuntimeEntry?>>();

            foreach (var pid in procEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await semaphore.WaitAsync(cancellationToken);
                tasks.Add(ReadProcessAsync(pid, semaphore, cancellationToken));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var entry in results)
            {
                if (entry == null) continue;
                anyReadable = true;
                if (!entry.CmdlineReadable)
                    cmdlineUnreadableCount++;
                if (!entry.MemoryMapsReadable)
                    mapsUnreadableCount++;
                if (!entry.EnvironmentReadable)
                    environUnreadableCount++;
                if (!entry.ExePathReadable)
                    exeUnreadableCount++;
                builder.AddProcessRuntime(entry);
                processedCount++;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "/proc",
                Status = CapabilityStatus.Unavailable,
                Detail = $"Error: {ex.Message}. Scanned {processedCount} processes before failure.",
                Command = "/proc/<pid>/*"
            });
            return;
        }

        var unreadableCount = cmdlineUnreadableCount + mapsUnreadableCount + environUnreadableCount + exeUnreadableCount;
        var status = anyReadable
            ? (unreadableCount > 0 ? CapabilityStatus.PermissionLimited : CapabilityStatus.Available)
            : CapabilityStatus.Unavailable;

        var detail = $"{processedCount} processes scanned";
        if (unreadableCount > 0)
        {
            detail += $"; unreadable: cmdline={cmdlineUnreadableCount}, maps={mapsUnreadableCount}, environ={environUnreadableCount}, exe={exeUnreadableCount}";
        }

        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "/proc",
            Status = status,
            Detail = detail,
            Command = "/proc/<pid>/*"
        });
    }

    private static async Task<ProcessRuntimeEntry?> ReadProcessAsync(int pid, SemaphoreSlim semaphore, CancellationToken ct)
    {
        try
        {
            var status = await ReadStatusAsync(pid, ct);
            if (status == null)
            {
                semaphore.Release();
                return null;
            }

            var comm = await TryReadAsync(() => ReadCommAsync(pid, ct), ct);
            var exePath = await TryReadAsync(() => ReadExePathAsync(pid, ct), ct);
            var cmdlineResult = await TryReadAsync(() => ReadCmdlineAsync(pid, ct), ct);
            var mapsResult = await TryReadAsync(() => ReadMapsAsync(pid, ct), ct);
            var environResult = await TryReadAsync(() => ReadEnvironAsync(pid, ct), ct);

            semaphore.Release();

            string? cmdline = cmdlineResult.Content;
            bool cmdlineReadable = cmdlineResult.Content != null;
            bool cmdlineTruncated = cmdlineResult.Truncated;
            List<ProcessMemoryMap>? maps = mapsResult.Maps;
            bool mapsReadable = mapsResult.Maps != null;
            bool mapsTruncated = mapsResult.Truncated;
            List<string>? environ = environResult.Entries;
            bool environReadable = environResult.Entries != null;
            bool environTruncated = environResult.Truncated;
            bool exeReadable = exePath != null;

            return new ProcessRuntimeEntry
            {
                Pid = pid,
                Name = comm ?? status.Value.Name,
                ExePath = exePath ?? string.Empty,
                Cmdline = cmdline ?? string.Empty,
                CmdlineReadable = cmdlineReadable,
                Ppid = status.Value.Ppid,
                Uid = status.Value.Uid,
                StatusDuplicateFieldCount = status.Value.DuplicateFieldCount,
                CmdlineTruncated = cmdlineTruncated,
                MapsTruncated = mapsTruncated,
                EnvironTruncated = environTruncated,
                MemoryMaps = maps?.ToArray() ?? Array.Empty<ProcessMemoryMap>(),
                MemoryMapsReadable = mapsReadable,
                Environment = environ?.ToArray() ?? Array.Empty<string>(),
                EnvironmentReadable = environReadable,
                ExePathReadable = exeReadable
            };
        }
        catch (OperationCanceledException)
        {
            semaphore.Release();
            throw;
        }
        catch
        {
            semaphore.Release();
            return null;
        }
    }

    private static async Task<T?> TryReadAsync<T>(Func<Task<T?>> readFunc, CancellationToken ct)
    {
        try
        {
            return await readFunc();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return default;
        }
    }

    private static async Task<ProcessStatus?> ReadStatusAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/status";
        if (!File.Exists(path))
            return null;

        var text = await File.ReadAllTextAsync(path, ct);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        int ppid = 0;
        int uid = 0;
        string name = string.Empty;
        string state = string.Empty;
        int duplicateCount = 0;
        bool seenPpid = false, seenUid = false, seenName = false, seenState = false;

        foreach (var line in lines)
        {
            if (line.Length < 5)
                continue;

            if (line.StartsWith("PPid:", StringComparison.OrdinalIgnoreCase))
            {
                if (seenPpid) duplicateCount++;
                seenPpid = true;
                int.TryParse(line.AsSpan(5).TrimStart(), out ppid);
            }
            else if (line.StartsWith("Uid:", StringComparison.OrdinalIgnoreCase))
            {
                if (seenUid) duplicateCount++;
                seenUid = true;
                var parts = line.AsSpan(4).TrimStart().ToString().Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0)
                    int.TryParse(parts[0], out uid);
            }
            else if (line.StartsWith("Name:", StringComparison.OrdinalIgnoreCase))
            {
                if (seenName) duplicateCount++;
                seenName = true;
                name = line.AsSpan(5).TrimStart().ToString();
            }
            else if (line.StartsWith("State:", StringComparison.OrdinalIgnoreCase))
            {
                if (seenState) duplicateCount++;
                seenState = true;
                state = line.AsSpan(6).TrimStart().ToString();
            }
        }

        return new ProcessStatus(ppid, uid, name, state, duplicateCount);
    }

    private static async Task<string?> ReadCommAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/comm";
        if (!File.Exists(path))
            return null;

        var text = await File.ReadAllTextAsync(path, ct);
        return text.TrimEnd('\n');
    }

    private static async Task<string?> ReadExePathAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/exe";
        var (stdout, _, ok) = await ScannerCommandRunner.RunAsync("readlink", new[] { path }, ct);
        if (ok && !string.IsNullOrWhiteSpace(stdout))
            return stdout.Trim();
        return null;
    }

    private static async Task<(string? Content, bool Truncated)> ReadCmdlineAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/cmdline";
        if (!File.Exists(path))
            return (null, false);

        var (bytes, truncated) = await ReadProcFileAsync(path, MaxCmdlineBytes, ct);
        if (bytes.Length == 0)
            return (string.Empty, truncated);

        // Replace null bytes with spaces
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 0)
                bytes[i] = (byte)' ';
        }

        var result = Encoding.UTF8.GetString(bytes).Trim();
        return (result, truncated);
    }

    private static async Task<(List<ProcessMemoryMap>? Maps, bool Truncated)> ReadMapsAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/maps";
        if (!File.Exists(path))
            return (null, false);

        var (bytes, truncated) = await ReadProcFileAsync(path, MaxMapsBytes, ct);
        if (bytes.Length == 0)
            return (new List<ProcessMemoryMap>(), truncated);

        var text = Encoding.UTF8.GetString(bytes);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var maps = new List<ProcessMemoryMap>(lines.Length);

        foreach (var line in lines)
        {
            var map = ParseMapLine(line);
            if (map != null)
                maps.Add(map);
        }

        return (maps, truncated);
    }

    internal static ProcessMemoryMap? ParseMapLine(string line)
    {
        // Format: address perms offset dev inode pathname
        // Example: 00400000-0040c000 r-xp 00000000 08:01 1310734 /bin/cat
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 5)
            return null;

        var addressRange = parts[0];
        var perms = parts[1];

        // Validate address range is hex-hex
        if (!IsValidAddressRange(addressRange))
            return null;

        // Validate permissions are exactly 4 chars and only valid permission chars
        if (perms.Length != 4 || !perms.All(c => c is 'r' or 'w' or 'x' or 'p' or 's' or '-'))
            return null;

        string mappedPath;
        if (parts.Length > 5)
        {
            // pathname may contain spaces, so join everything from index 5 onward
            mappedPath = string.Join(' ', parts[5..]);
        }
        else
        {
            mappedPath = string.Empty;
        }

        return new ProcessMemoryMap
        {
            AddressRange = addressRange,
            Permissions = perms,
            Path = mappedPath
        };
    }

    private static bool IsValidAddressRange(string range)
    {
        // Expected format: hexaddr-hexaddr (e.g. 00400000-0040c000)
        var dashIndex = range.IndexOf('-');
        if (dashIndex <= 0 || dashIndex == range.Length - 1)
            return false;

        var before = range.AsSpan(0, dashIndex);
        var after = range.AsSpan(dashIndex + 1);

        return IsHex(before) && IsHex(after);
    }

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
            return false;
        foreach (var c in value)
        {
            if (!char.IsAsciiHexDigit(c))
                return false;
        }
        return true;
    }

    private static async Task<(List<string>? Entries, bool Truncated)> ReadEnvironAsync(int pid, CancellationToken ct)
    {
        var path = $"/proc/{pid}/environ";
        if (!File.Exists(path))
            return (null, false);

        var (bytes, truncated) = await ReadProcFileAsync(path, MaxEnvironBytes, ct);
        if (bytes.Length == 0)
            return (new List<string>(), truncated);

        var entries = new List<string>();
        int start = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 0)
            {
                var entry = Encoding.UTF8.GetString(bytes, start, i - start);
                if (!string.IsNullOrEmpty(entry))
                    entries.Add(entry);
                start = i + 1;
            }
        }

        if (start < bytes.Length)
        {
            var entry = Encoding.UTF8.GetString(bytes, start, bytes.Length - start);
            if (!string.IsNullOrEmpty(entry))
                entries.Add(entry);
        }

        return (entries, truncated);
    }

    /// <summary>
    /// Reads a procfs file with a read loop to handle partial reads, capping at maxBytes.
    /// Returns the data plus a flag indicating whether the file exceeded the cap.
    /// </summary>
    private static async Task<(byte[] Data, bool Truncated)> ReadProcFileAsync(string path, int maxBytes, CancellationToken ct)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        using var ms = new MemoryStream();
        var buffer = new byte[4096];
        int totalRead = 0;

        while (totalRead < maxBytes)
        {
            int toRead = Math.Min(buffer.Length, maxBytes - totalRead);
            int read = await fs.ReadAsync(buffer.AsMemory(0, toRead), ct);
            if (read == 0)
                break;

            ms.Write(buffer, 0, read);
            totalRead += read;
        }

        bool truncated = false;
        if (totalRead >= maxBytes)
        {
            int peek = await fs.ReadAsync(buffer.AsMemory(0, 1), ct);
            if (peek > 0)
                truncated = true;
        }

        return (ms.ToArray(), truncated);
    }

    private readonly record struct ProcessStatus(int Ppid, int Uid, string Name, string State, int DuplicateFieldCount);
}
