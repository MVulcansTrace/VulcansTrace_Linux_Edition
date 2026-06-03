namespace VulcansTrace.Linux.Core;

/// <summary>
/// Represents a directed correlation edge between two findings in a Trace Map.
/// </summary>
/// <param name="FromFindingId">The deterministic <see cref="Finding.Id"/> of the origin finding.</param>
/// <param name="ToFindingId">The deterministic <see cref="Finding.Id"/> of the destination finding.</param>
/// <param name="CorrelationType">The nature of the relationship.</param>
/// <param name="Narrative">A human-readable explanation of why these findings are connected.</param>
/// <param name="Confidence">Confidence level for this correlation.</param>
public sealed record CorrelationEdge(
    Guid FromFindingId,
    Guid ToFindingId,
    CorrelationType CorrelationType,
    string Narrative,
    CorrelationConfidence Confidence);
