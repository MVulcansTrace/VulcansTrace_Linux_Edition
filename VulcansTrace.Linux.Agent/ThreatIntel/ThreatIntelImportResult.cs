using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Result of importing a threat intelligence bundle.
/// </summary>
public sealed record ThreatIntelImportResult
{
    /// <summary>Extracted IOC entries ready for import.</summary>
    public IReadOnlyList<IocEntry> Entries { get; init; } = Array.Empty<IocEntry>();

    /// <summary>Number of IOCs successfully imported.</summary>
    public int ImportedCount => Entries.Count;

    /// <summary>Number of IOCs skipped (unparseable or unsupported).</summary>
    public int SkippedCount { get; init; }

    /// <summary>Warning messages produced during import.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}
