namespace VulcansTrace.Linux.Core;

/// <summary>
/// Represents a critical correlated attack chain detected by the Trace Map correlator.
/// </summary>
public sealed record CriticalChain
{
    /// <summary>The compromised internal host.</summary>
    public required string Host { get; init; }

    /// <summary>Human-readable description of the chain.</summary>
    public required string Narrative { get; init; }

    /// <summary>Ordered finding IDs that make up the chain.</summary>
    public required IReadOnlyList<Guid> FindingIds { get; init; }
}
