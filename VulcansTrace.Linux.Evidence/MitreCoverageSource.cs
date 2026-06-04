using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence;

/// <summary>
/// Describes a detector or rule that provides MITRE ATT&CK coverage.
/// </summary>
public sealed record MitreCoverageSource
{
    /// <summary>Stable source identifier, such as a detector type name or rule ID.</summary>
    public required string SourceId { get; init; }

    /// <summary>Human-readable source name or description.</summary>
    public required string SourceName { get; init; }

    /// <summary>Source category, such as "Detector" or "Rule".</summary>
    public required string SourceType { get; init; }

    /// <summary>MITRE ATT&CK techniques covered by this source.</summary>
    public required IReadOnlyList<MitreTechnique> MitreTechniques { get; init; }
}
