namespace VulcansTrace.Linux.Core;

/// <summary>
/// The output of a Trace Map correlator, containing the original findings
/// plus the directed correlation edges discovered between them.
/// </summary>
public sealed record TraceMapResult
{
    /// <summary>The original findings, unmodified.</summary>
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>Directed correlation edges between findings.</summary>
    public required IReadOnlyList<CorrelationEdge> Edges { get; init; }

    /// <summary>Critical attack chains detected across multiple categories.</summary>
    public IReadOnlyList<CriticalChain> CriticalChains { get; init; } = Array.Empty<CriticalChain>();
}
