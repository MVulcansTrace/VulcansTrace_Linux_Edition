using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="RiskScorecard"/> from a collection of findings.
/// </summary>
/// <remarks>
/// Scoring is deterministic and severity-driven:
/// <list type="bullet">
///   <item>Base deduction per finding = <c>SeverityValue * 5</c> (Critical = 20, High = 15, Medium = 10, Low = 5, Info = 0)</item>
///   <item>Each finding's deduction is multiplied by the average <see cref="CisBenchmarkMapping.ControlWeight"/> of its CIS mappings (default 1.0)</item>
///   <item>Numeric score = <c>Clamp(100 - totalDeduction, 0, 100)</c></item>
/// </list>
/// Letter grades: A (90+), B (80–89), C (70–79), D (60–69), F (&lt;60).
/// </remarks>
public sealed class RiskScorecardBuilder : IRiskScorecardBuilder
{
    /// <summary>
    /// Builds a risk scorecard from the given findings.
    /// </summary>
    /// <param name="findings">The findings to evaluate.</param>
    /// <param name="timestamp">Optional timestamp for the scorecard.</param>
    /// <returns>A risk scorecard, or <c>null</c> if no findings are provided.</returns>
    public RiskScorecard? Build(IReadOnlyList<Finding> findings, DateTime? timestamp = null)
    {
        if (findings == null)
            throw new ArgumentNullException(nameof(findings));

        if (findings.Count == 0)
            return null;

        var categoryAccumulators = new Dictionary<string, CategoryAccumulator>(StringComparer.OrdinalIgnoreCase);
        double totalDeduction = 0;
        int riskRelevantCount = 0;

        foreach (var finding in findings)
        {
            var severityValue = (int)finding.Severity;
            if (severityValue <= 0)
                continue; // Info findings contribute no risk

            riskRelevantCount++;
            double weight = GetAverageControlWeight(finding.CisMappings);
            double deduction = severityValue * 5.0 * weight;
            totalDeduction += deduction;

            if (!categoryAccumulators.TryGetValue(finding.Category, out var acc))
            {
                acc = new CategoryAccumulator();
                categoryAccumulators[finding.Category] = acc;
            }

            acc.Count++;
            acc.SeveritySum += severityValue;
            acc.Deduction += deduction;
        }

        var numericScore = Math.Max(0.0, 100.0 - totalDeduction);
        var (letterGrade, summaryStatus) = GradeAndStatus(numericScore);
        numericScore = Math.Round(numericScore, 1, MidpointRounding.AwayFromZero);

        var byCategory = categoryAccumulators
            .OrderByDescending(kvp => kvp.Value.Deduction)
            .Select(kvp => new CategoryRisk
            {
                Category = kvp.Key,
                FindingCount = kvp.Value.Count,
                TotalDeduction = Math.Round(kvp.Value.Deduction, 1),
                AverageSeverity = Math.Round(kvp.Value.SeveritySum / kvp.Value.Count, 1)
            })
            .ToList();

        return new RiskScorecard
        {
            NumericScore = numericScore,
            TotalDeduction = Math.Round(totalDeduction, 1, MidpointRounding.AwayFromZero),
            IsSaturated = totalDeduction > 100.0,
            LetterGrade = letterGrade,
            SummaryStatus = summaryStatus,
            TotalFindings = riskRelevantCount,
            ByCategory = byCategory,
            GeneratedAt = timestamp ?? DateTime.UtcNow
        };
    }

    private static double GetAverageControlWeight(IReadOnlyList<CisBenchmarkMapping>? mappings)
    {
        if (mappings == null || mappings.Count == 0)
            return 1.0;

        double sum = 0;
        foreach (var mapping in mappings)
        {
            var weight = mapping.ControlWeight;
            if (double.IsNaN(weight) || double.IsInfinity(weight) || weight <= 0 || weight > 1000.0)
                weight = 1.0;
            sum += weight;
        }

        return sum / mappings.Count;
    }

    private static (string Grade, string Status) GradeAndStatus(double score)
    {
        return score switch
        {
            >= RiskScorecard.AThreshold => ("A", "Low"),
            >= RiskScorecard.BThreshold => ("B", "Moderate"),
            >= RiskScorecard.CThreshold => ("C", "Elevated"),
            >= RiskScorecard.DThreshold => ("D", "High"),
            _ => ("F", "Severe")
        };
    }

    private sealed class CategoryAccumulator
    {
        public int Count;
        public double SeveritySum;
        public double Deduction;
    }
}
