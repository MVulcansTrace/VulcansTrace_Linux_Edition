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

    /// <summary>Findings present in both audits with unchanged severity.</summary>
    public IReadOnlyList<DiffFinding> UnchangedFindings { get; init; } = Array.Empty<DiffFinding>();

    /// <summary>Human-readable summary of the diff.</summary>
    public string Summary => $"{NewFindings.Count} new, {ResolvedFindings.Count} resolved, {WorsenedFindings.Count} worsened, {ImprovedFindings.Count} improved.";
}

/// <summary>
/// A finding represented in a diff.
/// </summary>
public sealed record DiffFinding
{
    public required string RuleId { get; init; }
    public required string Target { get; init; }
    public required string Severity { get; init; }
    public required string ShortDescription { get; init; }
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
    public required string ShortDescription { get; init; }
}
