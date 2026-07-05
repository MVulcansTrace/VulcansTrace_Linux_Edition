namespace VulcansTrace.Linux.Agent.Findings;

/// <summary>
/// Represents a finding that the user has pinned for later reference.
/// The stable <see cref="Fingerprint"/> is the primary key.
/// </summary>
public sealed record PinnedFinding
{
    /// <summary>
    /// Stable fingerprint of the pinned finding. This is the primary key.
    /// </summary>
    public required string Fingerprint { get; init; }

    /// <summary>Optional rule identifier (e.g., "FW-001"). May be null for engine findings.</summary>
    public string? RuleId { get; init; }

    /// <summary>Finding category (e.g., PortScan).</summary>
    public required string Category { get; init; }

    /// <summary>Severity label (e.g., "High").</summary>
    public required string Severity { get; init; }

    /// <summary>Source host IP address or description.</summary>
    public required string SourceHost { get; init; }

    /// <summary>Target of the activity (IP, port, or description).</summary>
    public required string Target { get; init; }

    /// <summary>Brief description displayed in the UI.</summary>
    public required string ShortDescription { get; init; }

    /// <summary>UTC timestamp when the finding was pinned.</summary>
    public DateTime PinnedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Optional user note attached to the pinned finding.</summary>
    public string Notes { get; init; } = string.Empty;
}
