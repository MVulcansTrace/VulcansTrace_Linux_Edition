using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Escalates finding severity when correlated threat patterns are detected.
/// </summary>
/// <remarks>
/// Detects correlated threat patterns and escalates their severity:
/// - "Beaconing + Lateral Movement": Indicates compromised host with C2 communication + internal probing
/// - "Flag Anomaly + Port Scan": Advanced evasion techniques combined with reconnaissance
/// - "MAC Spoofing + Interface Hopping": Sophisticated attack attempting to bypass network controls
/// Such findings are escalated to Critical severity for immediate attention.
/// Only findings whose category participates in the correlation pair are escalated.
/// </remarks>
public sealed class RiskEscalator
{
    /// <summary>
    /// Processes findings and escalates severity when correlated threat patterns are detected.
    /// </summary>
    /// <param name="findings">The findings to evaluate for escalation.</param>
    /// <returns>
    /// A new collection of findings with escalated severities where applicable.
    /// Original findings are not modified; new instances are created using the <c>with</c> expression.
    /// </returns>
    public IReadOnlyList<Core.Finding> Escalate(IReadOnlyList<Core.Finding> findings)
    {
        if (findings.Count == 0)
            return Array.Empty<Core.Finding>();

        var result = new List<Core.Finding>(findings.Count);

        var byHost = findings.GroupBy(f => f.SourceHost);
        foreach (var group in byHost)
        {
            var groupFindings = group.ToList();
            var categories = groupFindings.Select(f => f.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var hasBeacon = categories.Contains(Core.FindingCategories.Beaconing);
            var hasLateral = categories.Contains(Core.FindingCategories.LateralMovement);
            var hasFlagAnomaly = categories.Contains(Core.FindingCategories.FlagAnomaly);
            var hasPortScan = categories.Contains(Core.FindingCategories.PortScan);
            var hasMacSpoofing = categories.Contains(Core.FindingCategories.MacSpoofing);
            var hasInterfaceHopping = categories.Contains(Core.FindingCategories.InterfaceHopping);

            // Windows-style correlation: Beaconing + Lateral Movement
            var shouldEscalateBeaconLateral = hasBeacon && hasLateral
                && AreTimeRangesCorrelated(groupFindings, FindingCategories.Beaconing, FindingCategories.LateralMovement);

            // Linux-specific correlations
            var shouldEscalateFlagPort = hasFlagAnomaly && hasPortScan
                && AreTimeRangesCorrelated(groupFindings, FindingCategories.FlagAnomaly, FindingCategories.PortScan);
            var shouldEscalateMacInterface = hasMacSpoofing && hasInterfaceHopping
                && AreTimeRangesCorrelated(groupFindings, FindingCategories.MacSpoofing, FindingCategories.InterfaceHopping);

            foreach (var f in groupFindings)
            {
                var participates =
                    (shouldEscalateBeaconLateral && (IsCategory(f, FindingCategories.Beaconing) || IsCategory(f, FindingCategories.LateralMovement)))
                    || (shouldEscalateFlagPort && (IsCategory(f, FindingCategories.FlagAnomaly) || IsCategory(f, FindingCategories.PortScan)))
                    || (shouldEscalateMacInterface && (IsCategory(f, FindingCategories.MacSpoofing) || IsCategory(f, FindingCategories.InterfaceHopping)));

                if (participates && f.Severity < Core.Severity.Critical)
                    result.Add(f with { Severity = Core.Severity.Critical });
                else
                    result.Add(f);
            }
        }

        return result;
    }

    private static bool AreTimeRangesCorrelated(IReadOnlyList<Core.Finding> groupFindings, string category1, string category2)
    {
        var findings1 = groupFindings.Where(f => IsCategory(f, category1)).ToList();
        var findings2 = groupFindings.Where(f => IsCategory(f, category2)).ToList();

        if (findings1.Count == 0 || findings2.Count == 0)
            return false;

        const double maxGapHours = 24.0;

        // Sort by start time so we can use a sliding window instead of checking all pairs.
        var sorted1 = findings1.OrderBy(f => f.TimeRangeStart).ToList();
        var sorted2 = findings2.OrderBy(f => f.TimeRangeStart).ToList();

        int startIdx = 0;
        foreach (var f1 in sorted1)
        {
            // Advance startIdx past f2s that end more than 24h before f1 starts.
            while (startIdx < sorted2.Count &&
                   sorted2[startIdx].TimeRangeEnd < f1.TimeRangeStart &&
                   (f1.TimeRangeStart - sorted2[startIdx].TimeRangeEnd).TotalHours > maxGapHours)
            {
                startIdx++;
            }

            for (int i = startIdx; i < sorted2.Count; i++)
            {
                var f2 = sorted2[i];

                // If f2 starts more than 24h after f1 ends, all later f2s will too.
                if (f2.TimeRangeStart > f1.TimeRangeEnd &&
                    (f2.TimeRangeStart - f1.TimeRangeEnd).TotalHours > maxGapHours)
                {
                    break;
                }

                if (GetTimeGapHours(f1, f2) <= maxGapHours)
                    return true;
            }
        }

        return false;
    }

    private static double GetTimeGapHours(Core.Finding a, Core.Finding b)
    {
        if (a.TimeRangeEnd >= b.TimeRangeStart && b.TimeRangeEnd >= a.TimeRangeStart)
            return 0;

        if (a.TimeRangeEnd < b.TimeRangeStart)
            return (b.TimeRangeStart - a.TimeRangeEnd).TotalHours;

        return (a.TimeRangeStart - b.TimeRangeEnd).TotalHours;
    }

    private static bool IsCategory(Core.Finding f, string category) =>
        string.Equals(f.Category, category, StringComparison.OrdinalIgnoreCase);
}
