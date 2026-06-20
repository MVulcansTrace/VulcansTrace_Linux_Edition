namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Records that a category was audited at a specific point in time.
/// Used to build long-horizon coverage maps of which audit areas have
/// been checked across sessions.
/// </summary>
public sealed record CategoryAuditEntry
{
    /// <summary>The audit category that was checked (e.g., "SSH").</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>UTC timestamp when the category was last audited.</summary>
    public DateTime UtcTimestamp { get; init; } = DateTime.UtcNow;
}
