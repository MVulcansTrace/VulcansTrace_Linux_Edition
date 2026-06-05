namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Represents a single running process snapshot gathered from /proc/&lt;pid&gt;/.
/// </summary>
public sealed record ProcessRuntimeEntry
{
    /// <summary>Process ID.</summary>
    public int Pid { get; init; }

    /// <summary>Process name from /proc/&lt;pid&gt;/comm.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Resolved executable path from readlink /proc/&lt;pid&gt;/exe.</summary>
    public string ExePath { get; init; } = string.Empty;

    /// <summary>Command line from /proc/&lt;pid&gt;/cmdline with null bytes replaced by spaces.</summary>
    public string Cmdline { get; init; } = string.Empty;

    /// <summary>True when /proc/&lt;pid&gt;/cmdline was successfully read, even if it was empty.</summary>
    public bool CmdlineReadable { get; init; }

    /// <summary>Parent process ID from /proc/&lt;pid&gt;/status.</summary>
    public int Ppid { get; init; }

    /// <summary>Real UID from /proc/&lt;pid&gt;/status.</summary>
    public int Uid { get; init; }

    /// <summary>
    /// Number of duplicate fields detected in /proc/&lt;pid&gt;/status.
    /// Non-zero indicates anomalous or tampered procfs input.
    /// </summary>
    public int StatusDuplicateFieldCount { get; init; }

    /// <summary>Memory map entries from /proc/&lt;pid&gt;/maps.</summary>
    public IReadOnlyList<ProcessMemoryMap> MemoryMaps { get; init; } = Array.Empty<ProcessMemoryMap>();

    /// <summary>True when /proc/&lt;pid&gt;/maps was successfully read, even if it contained no mappings.</summary>
    public bool MemoryMapsReadable { get; init; }

    /// <summary>
    /// True if /proc/&lt;pid&gt;/cmdline exceeded the read cap and was truncated.
    /// </summary>
    public bool CmdlineTruncated { get; init; }

    /// <summary>
    /// True if /proc/&lt;pid&gt;/environ exceeded the read cap and was truncated.
    /// </summary>
    public bool EnvironTruncated { get; init; }

    /// <summary>
    /// True if /proc/&lt;pid&gt;/maps exceeded the read cap and was truncated.
    /// </summary>
    public bool MapsTruncated { get; init; }

    /// <summary>Environment variables from /proc/&lt;pid&gt;/environ (key=value).</summary>
    public IReadOnlyList<string> Environment { get; init; } = Array.Empty<string>();

    /// <summary>True when /proc/&lt;pid&gt;/environ was successfully read, even if it was empty.</summary>
    public bool EnvironmentReadable { get; init; }

    /// <summary>True when /proc/&lt;pid&gt;/exe was successfully resolved.</summary>
    public bool ExePathReadable { get; init; }
}
