namespace VulcansTrace.Linux.Core.ThreatIntel;

/// <summary>
/// A single indicator of compromise imported from a threat intelligence feed.
/// </summary>
public sealed record IocEntry
{
    /// <summary>The type of IOC.</summary>
    public IocType Type { get; init; }

    /// <summary>The canonical IOC value (e.g., IP address, hash hex string, port number as string).</summary>
    public string Value { get; init; } = string.Empty;

    /// <summary>Confidence score from 0 (lowest) to 100 (highest).</summary>
    public int Confidence { get; init; } = 50;

    /// <summary>Source feed name, e.g. "STIX" or "MISP".</summary>
    public string Source { get; init; } = string.Empty;

    /// <summary>Optional human-readable description of the threat.</summary>
    public string? Description { get; init; }

    /// <summary>UTC timestamp when this IOC was imported.</summary>
    public DateTime ImportedAt { get; init; } = DateTime.UtcNow;

    /// <summary>Hash algorithm for FileHash IOCs (e.g. "SHA-256", "MD5", "SHA-1").</summary>
    public string Algorithm { get; init; } = string.Empty;

    /// <summary>Storage key used for deduplication.</summary>
    public string StorageKey => $"{(int)Type}|{Value}";
}
