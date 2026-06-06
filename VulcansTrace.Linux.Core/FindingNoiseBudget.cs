using System.IO;
using System.Net;

namespace VulcansTrace.Linux.Core;

/// <summary>
/// Groups semantically similar findings into representative findings and caps
/// the number of representatives shown for each category.
/// </summary>
public static class FindingNoiseBudget
{
    /// <summary>Default maximum number of representative findings per category.</summary>
    public const int DefaultMaxRepresentativesPerCategory = 100;

    /// <summary>
    /// Applies a per-category noise budget to the supplied findings.
    /// </summary>
    public static IReadOnlyList<Finding> Apply(
        IReadOnlyList<Finding> findings,
        int maxRepresentativesPerCategory,
        ICollection<string> warnings,
        string producerLabel = "detector")
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(warnings);

        if (maxRepresentativesPerCategory <= 0 || findings.Count == 0)
            return findings;

        var result = new List<Finding>();

        foreach (var categoryGroup in findings.GroupBy(f => f.Category))
        {
            var rawCount = categoryGroup.Count();
            var representatives = categoryGroup
                .GroupBy(GetGroupingKey)
                .Select(CreateRepresentative)
                .OrderByDescending(f => f.Severity)
                .ThenByDescending(f => f.GroupedCount)
                .ThenBy(f => GetGroupingKey(f), StringComparer.Ordinal)
                .ToList();

            if (representatives.Count > maxRepresentativesPerCategory)
            {
                warnings.Add($"{categoryGroup.Key} {producerLabel} produced {rawCount} findings, grouped into {representatives.Count} representatives (showing top {maxRepresentativesPerCategory}).");
            }

            result.AddRange(representatives.Take(maxRepresentativesPerCategory));
        }

        return result;
    }

    /// <summary>
    /// Returns the stable semantic grouping key for a finding.
    /// </summary>
    public static string GetGroupingKey(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var ruleId = finding.RuleId ?? string.Empty;
        var detailsKey = string.IsNullOrWhiteSpace(ruleId)
            ? NormalizeGroupingText(finding.Details)
            : string.Empty;

        return string.Join("|",
            ruleId,
            finding.Category,
            finding.SourceHost,
            NormalizeGroupingText(finding.ShortDescription),
            detailsKey);
    }

    /// <summary>
    /// Derives concise risk drivers for a representative group.
    /// </summary>
    public static IReadOnlyList<string> DeriveRiskDrivers(IEnumerable<Finding> group)
    {
        ArgumentNullException.ThrowIfNull(group);

        var findingsList = group.ToList();
        if (findingsList.Count == 0)
            return Array.Empty<string>();

        var pathTargets = findingsList
            .Where(f => f.Target.StartsWith('/'))
            .Select(f => Path.GetDirectoryName(f.Target))
            .Where(dir => !string.IsNullOrEmpty(dir))
            .ToList();

        if (pathTargets.Count > 0)
        {
            return pathTargets
                .GroupBy(dir => dir, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.Ordinal)
                .Take(3)
                .Select(g => g.Key!)
                .ToList();
        }

        var ipTargets = findingsList
            .Select(f => TryExtractIpTarget(f.Target, out var ip) ? ip : string.Empty)
            .Where(ip => !string.IsNullOrEmpty(ip))
            .ToList();

        if (ipTargets.Count > 0)
        {
            return ipTargets
                .GroupBy(ip => ip, StringComparer.Ordinal)
                .OrderByDescending(g => g.Count())
                .ThenBy(g => g.Key, StringComparer.Ordinal)
                .Take(3)
                .Select(g => g.Key)
                .ToList();
        }

        return findingsList
            .GroupBy(f => f.SourceHost, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .Take(2)
            .Select(g => g.Key)
            .ToList();
    }

    private static Finding CreateRepresentative(IEnumerable<Finding> group)
    {
        var findings = group.ToList();
        var representative = findings
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.TimeRangeEnd)
            .First();

        return representative with
        {
            TimeRangeStart = findings.Min(f => f.TimeRangeStart),
            TimeRangeEnd = findings.Max(f => f.TimeRangeEnd),
            GroupedCount = findings.Count,
            RepresentativeTargets = findings
                .Select(f => f.Target)
                .Distinct(StringComparer.Ordinal)
                .Take(5)
                .ToList(),
            RiskDrivers = DeriveRiskDrivers(findings)
        };
    }

    private static string NormalizeGroupingText(string value) =>
        string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static bool TryExtractIpTarget(string target, out string ip)
    {
        ip = string.Empty;
        if (string.IsNullOrWhiteSpace(target))
            return false;

        var trimmed = target.Trim();
        if (IPAddress.TryParse(trimmed, out var address))
        {
            ip = address.ToString();
            return true;
        }

        if (trimmed.StartsWith('['))
        {
            var bracketEnd = trimmed.IndexOf(']');
            if (bracketEnd <= 1)
                return false;

            var candidate = trimmed[1..bracketEnd];
            if (!IPAddress.TryParse(candidate, out address))
                return false;

            ip = address.ToString();
            return true;
        }

        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon <= 0)
            return false;

        var hostPart = trimmed[..lastColon];
        if (!IPAddress.TryParse(hostPart, out address))
            return false;

        ip = address.ToString();
        return true;
    }
}
