using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Discovers posture correlations between findings.
/// </summary>
public interface IPostureCorrelator
{
    /// <summary>
    /// Analyzes findings and returns posture correlations where known dangerous pairs are detected.
    /// </summary>
    /// <param name="findings">The findings to analyze.</param>
    /// <returns>A list of detected posture correlations.</returns>
    IReadOnlyList<PostureCorrelation> Correlate(IReadOnlyList<Finding> findings);
}
