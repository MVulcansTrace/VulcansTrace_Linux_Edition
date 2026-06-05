namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Represents a single memory mapping entry parsed from /proc/&lt;pid&gt;/maps.
/// </summary>
public sealed record ProcessMemoryMap
{
    /// <summary>Address range, e.g. "00400000-0040c000".</summary>
    public string AddressRange { get; init; } = string.Empty;

    /// <summary>Permissions, e.g. "r-xp".</summary>
    public string Permissions { get; init; } = string.Empty;

    /// <summary>Mapped file path, or pseudo-paths like "[heap]", "[stack]", "[vdso]".</summary>
    public string Path { get; init; } = string.Empty;
}
