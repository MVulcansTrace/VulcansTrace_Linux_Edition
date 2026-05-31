using System.Collections.Generic;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Computes trend direction text and arrow for compliance scorecards.
/// </summary>
public static class ComplianceTrendAnalyzer
{
    /// <summary>
    /// Computes the trend direction and arrow based on the current score and historical trend.
    /// </summary>
    /// <param name="trend">Historical trend points (previous audits).</param>
    /// <param name="currentScore">The current audit's overall score.</param>
    /// <returns>A tuple of (directionText, arrow).</returns>
    public static (string Direction, string Arrow) ComputeDirection(
        IReadOnlyList<ComplianceTrendPoint> trend,
        double currentScore)
    {
        if (trend.Count == 0)
        {
            return ("No trend data yet", "");
        }

        var previous = trend[^1].OverallScore;
        var delta = currentScore - previous;

        if (delta > 0.5)
        {
            return ($"Improving (+{delta:F1}%)", "↗");
        }

        if (delta < -0.5)
        {
            return ($"Declining ({delta:F1}%)", "↘");
        }

        return ("Stable", "→");
    }
}
