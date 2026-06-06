using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Represents the difference between two agent audits.
/// </summary>
public sealed record AuditDiff
{
    /// <summary>Findings present in the newer audit but not the older one.</summary>
    public IReadOnlyList<DiffFinding> NewFindings { get; init; } = Array.Empty<DiffFinding>();

    /// <summary>Findings present in the older audit but not the newer one.</summary>
    public IReadOnlyList<DiffFinding> ResolvedFindings { get; init; } = Array.Empty<DiffFinding>();

    /// <summary>Findings whose severity increased.</summary>
    public IReadOnlyList<SeverityChangeFinding> WorsenedFindings { get; init; } = Array.Empty<SeverityChangeFinding>();

    /// <summary>Findings whose severity decreased.</summary>
    public IReadOnlyList<SeverityChangeFinding> ImprovedFindings { get; init; } = Array.Empty<SeverityChangeFinding>();

    /// <summary>Findings whose confidence changed while severity stayed the same.</summary>
    public IReadOnlyList<ConfidenceChangeFinding> ConfidenceChangedFindings { get; init; } = Array.Empty<ConfidenceChangeFinding>();

    /// <summary>Findings present in both audits with unchanged severity.</summary>
    public IReadOnlyList<DiffFinding> UnchangedFindings { get; init; } = Array.Empty<DiffFinding>();

    /// <summary>Human-readable summary of the diff.</summary>
    public string Summary => $"{NewFindings.Count} new, {ResolvedFindings.Count} resolved, {WorsenedFindings.Count} worsened, {ImprovedFindings.Count} improved, {ConfidenceChangedFindings.Count} confidence changed.";

    /// <summary>Deterministic narrative summary of the diff for immediate comprehension.</summary>
    public string Narrative
    {
        get
        {
            var parts = new List<string>();

            // Resolved findings
            if (ResolvedFindings.Count > 0)
            {
                parts.Add($"{ResolvedFindings.Count} finding{(ResolvedFindings.Count != 1 ? "s" : "")} resolved");
            }

            // New findings with severity call-outs
            if (NewFindings.Count > 0)
            {
                var criticalCount = NewFindings.Count(f => IsSeverity(f, "Critical"));
                var highCount = NewFindings.Count(f => IsSeverity(f, "High"));

                if (NewFindings.Count == 1 && criticalCount == 1)
                {
                    parts.Add("1 new Critical finding");
                }
                else if (criticalCount > 0)
                {
                    if (highCount > 0)
                    {
                        parts.Add($"{NewFindings.Count} new findings ({criticalCount} Critical, {highCount} High)");
                    }
                    else
                    {
                        parts.Add($"{NewFindings.Count} new findings ({criticalCount} Critical)");
                    }
                }
                else if (highCount > 0)
                {
                    parts.Add($"{NewFindings.Count} new findings ({highCount} High)");
                }
                else
                {
                    parts.Add($"{NewFindings.Count} new finding{(NewFindings.Count != 1 ? "s" : "")}");
                }
            }

            // Worsened findings
            if (WorsenedFindings.Count > 0)
            {
                parts.Add($"{WorsenedFindings.Count} finding{(WorsenedFindings.Count != 1 ? "s" : "")} worsened");
            }

            // Improved findings
            if (ImprovedFindings.Count > 0)
            {
                parts.Add($"{ImprovedFindings.Count} finding{(ImprovedFindings.Count != 1 ? "s" : "")} improved");
            }

            if (ConfidenceChangedFindings.Count > 0)
            {
                parts.Add($"{ConfidenceChangedFindings.Count} finding{(ConfidenceChangedFindings.Count != 1 ? "s" : "")} changed confidence");
            }

            if (parts.Count == 0)
            {
                return "No changes between audits.";
            }

            parts.AddRange(GetUnchangedRiskParts());

            return string.Join(", ", parts) + ".";
        }
    }

    private static bool IsSeverity(DiffFinding finding, string severity) =>
        finding.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase);

    private List<string> GetUnchangedRiskParts()
    {
        var unchangedRiskAreas = new[]
        {
            new RiskArea("SSH exposure", new[] { "FW-002", "PORT-001", "SRV-003" }, new[] { "ssh" }),
            new RiskArea("Database exposure", new[] { "PORT-003" }, new[] { "database", "mysql", "postgres", "mongodb", "redis", "mssql", "oracle" }),
            new RiskArea("Telnet exposure", new[] { "SRV-001" }, new[] { "telnet" }),
            new RiskArea("FTP exposure", new[] { "SRV-002" }, new[] { "ftp" }),
        };

        var result = new List<string>();

        foreach (var area in unchangedRiskAreas)
        {
            bool hasUnchanged = UnchangedFindings.Any(f => MatchesRiskArea(f, area));
            bool hasChanged = NewFindings.Any(f => MatchesRiskArea(f, area))
                || ResolvedFindings.Any(f => MatchesRiskArea(f, area))
                || WorsenedFindings.Any(f => MatchesRiskArea(f, area))
                || ImprovedFindings.Any(f => MatchesRiskArea(f, area));

            if (hasUnchanged && !hasChanged)
            {
                result.Add($"{area.Label} unchanged");
            }
        }

        // Limit to at most two stable-risk notes to keep the narrative concise.
        return result.Take(2).ToList();
    }

    private static bool MatchesRiskArea(DiffFinding finding, RiskArea area) =>
        MatchesRiskArea(finding.RuleId, finding.ShortDescription, area);

    private static bool MatchesRiskArea(SeverityChangeFinding finding, RiskArea area) =>
        MatchesRiskArea(finding.RuleId, finding.ShortDescription, area);

    private static bool MatchesRiskArea(string ruleId, string shortDescription, RiskArea area)
    {
        if (area.RuleIds.Any(id => ruleId.Equals(id, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return area.Keywords.Any(keyword => shortDescription.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    private sealed record RiskArea(string Label, string[] RuleIds, string[] Keywords);
}

/// <summary>
/// A finding represented in a diff.
/// </summary>
public sealed record DiffFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string Severity { get; init; }
    public string Confidence { get; init; } = string.Empty;
    public IReadOnlyList<VulcansTrace.Linux.Core.EvidenceSignal> EvidenceSignals { get; init; } = Array.Empty<VulcansTrace.Linux.Core.EvidenceSignal>();
    public string EvidenceSignalsDisplay => EvidenceSignals.Count == 0
        ? string.Empty
        : string.Join(", ", EvidenceSignals.Select(s => s.Name));
    public required string ShortDescription { get; init; }

    /// <summary>Stable fingerprint for matching this finding across audits.</summary>
    public string? Fingerprint { get; init; }
}

/// <summary>
/// A finding whose severity changed between two audits.
/// </summary>
public sealed record SeverityChangeFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string OldSeverity { get; init; }
    public required string NewSeverity { get; init; }
    public string OldConfidence { get; init; } = string.Empty;
    public string NewConfidence { get; init; } = string.Empty;
    public IReadOnlyList<VulcansTrace.Linux.Core.EvidenceSignal> EvidenceSignals { get; init; } = Array.Empty<VulcansTrace.Linux.Core.EvidenceSignal>();
    public string EvidenceSignalsDisplay => EvidenceSignals.Count == 0
        ? string.Empty
        : string.Join(", ", EvidenceSignals.Select(s => s.Name));
    public required string ShortDescription { get; init; }

    /// <summary>Stable fingerprint for matching this finding across audits.</summary>
    public string? Fingerprint { get; init; }
}

/// <summary>
/// A finding whose detection confidence changed while severity stayed the same.
/// </summary>
public sealed record ConfidenceChangeFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string Severity { get; init; }
    public required string OldConfidence { get; init; }
    public required string NewConfidence { get; init; }
    public IReadOnlyList<VulcansTrace.Linux.Core.EvidenceSignal> EvidenceSignals { get; init; } = Array.Empty<VulcansTrace.Linux.Core.EvidenceSignal>();
    public string EvidenceSignalsDisplay => EvidenceSignals.Count == 0
        ? string.Empty
        : string.Join(", ", EvidenceSignals.Select(s => s.Name));
    public required string ShortDescription { get; init; }

    /// <summary>Stable fingerprint for matching this finding across audits.</summary>
    public string? Fingerprint { get; init; }
}
