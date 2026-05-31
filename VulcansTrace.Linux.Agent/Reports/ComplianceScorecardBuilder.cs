using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core.Compliance;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="ComplianceScorecard"/> from agent rule results and optional audit history.
/// </summary>
public sealed class ComplianceScorecardBuilder : IComplianceScorecardBuilder
{
    /// <summary>
    /// Builds a compliance scorecard from the given rule results and history store.
    /// </summary>
    /// <param name="ruleResults">All rule results from the audit.</param>
    /// <param name="historyStore">Optional history store for trend data.</param>
    /// <param name="timestamp">Timestamp for the scorecard.</param>
    /// <returns>A compliance scorecard, or null if no rules have CIS mappings.</returns>
    public ComplianceScorecard? Build(
        IReadOnlyList<RuleResult> ruleResults,
        IAuditHistoryStore? historyStore = null,
        DateTime? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(ruleResults);

        var familyData = new Dictionary<string, FamilyAccumulator>(StringComparer.OrdinalIgnoreCase);
        int overallTotal = 0;
        int overallPassed = 0;
        int overallCrashed = 0;

        foreach (var result in ruleResults)
        {
            if (result.CisMappings.Count == 0)
                continue;

            var familyIds = result.CisMappings
                .Select(m => CisFamilyResolver.ExtractFamilyId(m.ControlId))
                .Where(id => id != null)
                .Select(id => id!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (familyIds.Count == 0)
                continue;

            // Track overall score at the rule level (each rule counted once)
            if (result.Status != RuleStatus.NotApplicable && result.Status != RuleStatus.Suppressed)
            {
                overallTotal++;
                switch (result.Status)
                {
                    case RuleStatus.Passed:
                        overallPassed++;
                        break;
                    case RuleStatus.Crashed:
                        overallCrashed++;
                        break;
                    default:
                        // Failed (or any future status): counts toward total but not as passed/crashed
                        break;
                }
            }

            foreach (var familyId in familyIds)
            {
                if (!familyData.TryGetValue(familyId, out var acc))
                {
                    acc = new FamilyAccumulator();
                    familyData[familyId] = acc;
                }

                if (result.Status == RuleStatus.NotApplicable)
                    continue;

                acc.Total++;
                switch (result.Status)
                {
                    case RuleStatus.Passed:
                        acc.Passed++;
                        break;
                    case RuleStatus.Failed:
                        acc.Failed++;
                        break;
                    case RuleStatus.Crashed:
                        acc.Crashed++;
                        break;
                    case RuleStatus.Suppressed:
                        acc.Suppressed++;
                        break;
                    default:
                        // NotApplicable is filtered before this switch; default is defensive
                        break;
                }
            }
        }

        var familyScores = new List<ControlFamilyScore>(familyData.Count);
        bool hasFail = false;
        bool hasWarn = false;

        foreach (var kvp in familyData.OrderBy(k => int.TryParse(k.Key, out var n) ? n : int.MaxValue))
        {
            var acc = kvp.Value;
            if (acc.Total == 0)
                continue; // Family only had NotApplicable rules — skip

            var applicableTotal = acc.Total - acc.Suppressed;
            var rawScore = applicableTotal > 0 ? (double)acc.Passed / applicableTotal * 100.0 : 100.0;
            var score = Math.Round(rawScore, 1);
            var status = DetermineFamilyStatus(acc, score);

            if (status == "Fail")
                hasFail = true;
            else if (status == "Warn")
                hasWarn = true;

            familyScores.Add(new ControlFamilyScore
            {
                FamilyId = kvp.Key,
                FamilyName = CisFamilyResolver.GetFamilyName(kvp.Key),
                TotalControls = acc.Total,
                PassedControls = acc.Passed,
                FailedControls = acc.Failed,
                CrashedControls = acc.Crashed,
                SuppressedControls = acc.Suppressed,
                ScorePercentage = score,
                Status = status
            });
        }

        if (familyScores.Count == 0)
            return null;

        var overallRawScore = overallTotal > 0 ? (double)overallPassed / overallTotal * 100.0 : 100.0;
        var overallScore = Math.Round(overallRawScore, 1);
        var overallStatus = DetermineOverallStatus(overallScore, overallCrashed, hasFail, hasWarn);

        var trend = BuildTrend(historyStore);

        return new ComplianceScorecard
        {
            OverallScore = overallScore,
            SummaryStatus = overallStatus,
            FamilyScores = familyScores,
            Trend = trend,
            GeneratedAt = timestamp ?? DateTime.UtcNow
        };
    }

    private static string DetermineFamilyStatus(FamilyAccumulator acc, double score)
    {
        if (score >= ComplianceScorecard.PassThreshold && acc.Crashed == 0)
            return "Pass";
        if (score < ComplianceScorecard.WarnThreshold || acc.Crashed > 0)
            return "Fail";
        return "Warn";
    }

    private static string DetermineOverallStatus(double overallScore, int overallCrashed, bool hasFailFamily, bool hasWarnFamily)
    {
        if (overallScore < ComplianceScorecard.WarnThreshold || overallCrashed > 0 || hasFailFamily)
            return "Fail";
        if (overallScore < ComplianceScorecard.PassThreshold || hasWarnFamily)
            return "Warn";
        return "Pass";
    }

    private const int MaxTrendPoints = 10;

    private static IReadOnlyList<ComplianceTrendPoint> BuildTrend(IAuditHistoryStore? historyStore)
    {
        if (historyStore == null)
            return Array.Empty<ComplianceTrendPoint>();

        var history = historyStore.GetAll();
        if (history.Count == 0)
            return Array.Empty<ComplianceTrendPoint>();

        var entries = history
            .Where(h => h.Scorecard != null)
            .OrderBy(h => h.TimestampUtc)
            .TakeLast(MaxTrendPoints)
            .ToList();

        var points = new List<ComplianceTrendPoint>(entries.Count);
        foreach (var entry in entries)
        {
            points.Add(new ComplianceTrendPoint
            {
                Timestamp = entry.TimestampUtc,
                OverallScore = entry.Scorecard!.OverallScore
            });
        }

        return points;
    }

    private sealed class FamilyAccumulator
    {
        public int Total;
        public int Passed;
        public int Failed;
        public int Crashed;
        public int Suppressed;
    }
}
