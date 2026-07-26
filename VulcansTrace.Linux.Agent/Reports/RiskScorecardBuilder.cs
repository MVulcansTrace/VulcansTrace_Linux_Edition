using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="RiskScorecard"/> from a collection of findings.
/// </summary>
/// <remarks>
/// <para>Scoring is severity-driven with diminishing returns so realistic audits no longer saturate:</para>
/// <list type="bullet">
///   <item>Each finding contributes a raw load of <c>SeverityValue * 5 * ControlWeight</c> (Critical = 20, High = 15, Medium = 10, Low = 5, Info = 0).</item>
///   <item>Raw load is accumulated per severity tier and also per category (<see cref="CategoryRisk.TotalDeduction"/> keeps the raw per-category load for ranking).</item>
///   <item>Each tier's effective deduction is damped against a cap — the most points that tier can ever cost — using <c>cap * (1 - e^(-load/cap))</c>. Caps: Critical 35, High 22, Medium 12, Low 5.</item>
///   <item>Numeric score = <c>Clamp(100 - Σ dampedTierDeductions, 0, 100)</c>.</item>
/// </list>
/// <para>
/// Capping means a finding's marginal cost shrinks as its tier fills, so a normal desktop (mostly
/// Medium/Low) is no longer indistinguishable from a critical system. <see cref="RiskScorecard.TotalDeduction"/>
/// reports the raw (undamped) load for transparency; <see cref="RiskScorecard.IsSaturated"/> is set when the
/// caps materially dampen the score (raw load exceeds the effective deduction by 10+ points).
/// </para>
/// Letter grades: A (90+), B (80–89), C (70–79), D (60–69), F (&lt;60).
/// </remarks>
public sealed class RiskScorecardBuilder : IRiskScorecardBuilder
{
    // Max points a severity tier can ever cost. Caps rise with severity so Criticals dominate, while
    // any number of Low findings can drop the score by at most 5 points. Sums to 74 → absolute floor ~26.
    private const double CriticalCap = 35.0;
    private const double HighCap = 22.0;
    private const double MediumCap = 12.0;
    private const double LowCap = 5.0;

    // Threshold of raw load shaved off by the caps before we flag the score as saturated/dampened.
    private const double SaturationShaveThreshold = 10.0;

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
        // tierLoads is indexed by Severity value (Info=0 .. Critical=4); only Low..Critical are damped.
        var tierLoads = new double[5];
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
            tierLoads[severityValue] += deduction;

            if (!categoryAccumulators.TryGetValue(finding.Category, out var acc))
            {
                acc = new CategoryAccumulator();
                categoryAccumulators[finding.Category] = acc;
            }

            acc.Count++;
            acc.SeveritySum += severityValue;
            acc.Deduction += deduction;
        }

        // Damp each tier against its cap (diminishing returns), then sum for the effective deduction.
        var dampedDeduction =
            Damp(tierLoads[(int)Severity.Critical], CriticalCap) +
            Damp(tierLoads[(int)Severity.High], HighCap) +
            Damp(tierLoads[(int)Severity.Medium], MediumCap) +
            Damp(tierLoads[(int)Severity.Low], LowCap);

        var numericScore = Math.Clamp(100.0 - dampedDeduction, 0.0, 100.0);
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
            // Caps are materially shaping the score when they shave 10+ raw points off the deduction.
            IsSaturated = totalDeduction - dampedDeduction >= SaturationShaveThreshold,
            LetterGrade = letterGrade,
            SummaryStatus = summaryStatus,
            TotalFindings = riskRelevantCount,
            ByCategory = byCategory,
            GeneratedAt = timestamp ?? DateTime.UtcNow
        };
    }

    /// <summary>
    /// Damps a tier's raw load against its cap using diminishing returns: <c>cap * (1 - e^(-load/cap))</c>.
    /// The marginal cost of each additional finding shrinks as the tier fills, asymptoting at the cap.
    /// </summary>
    private static double Damp(double load, double cap)
    {
        if (cap <= 0.0 || load <= 0.0)
            return 0.0;
        return cap * (1.0 - Math.Exp(-load / cap));
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
