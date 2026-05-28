using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Immutable result returned by <see cref="IDetector.Detect"/> containing
/// both findings and warnings produced during analysis.
/// </summary>
/// <remarks>
/// Returning both findings and warnings from the Detect method eliminates
/// shared mutable state and makes detectors safe for concurrent or repeated use.
/// </remarks>
public sealed record DetectionResult
{
    /// <summary>Gets the security findings produced by the detector.</summary>
    public IReadOnlyList<Core.Finding> Findings { get; }

    /// <summary>Gets the warnings produced during analysis (e.g., truncation notices).</summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DetectionResult"/> class.
    /// </summary>
    /// <param name="findings">The security findings (may be empty).</param>
    /// <param name="warnings">The warnings (may be empty).</param>
    public DetectionResult(
        IReadOnlyList<Core.Finding> findings,
        IReadOnlyList<string> warnings)
    {
        Findings = findings ?? Array.Empty<Core.Finding>();
        Warnings = warnings ?? Array.Empty<string>();
    }

    /// <summary>
    /// Convenience constructor for findings with no warnings.
    /// </summary>
    public DetectionResult(IReadOnlyList<Core.Finding> findings)
        : this(findings, Array.Empty<string>())
    {
    }

    /// <summary>
    /// An empty result with no findings or warnings.
    /// </summary>
    public static DetectionResult Empty { get; } = new(Array.Empty<Core.Finding>(), Array.Empty<string>());
}
