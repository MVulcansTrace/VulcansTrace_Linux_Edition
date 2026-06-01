namespace VulcansTrace.Linux.Core;

/// <summary>
/// Risk breakdown for a single finding category.
/// </summary>
public sealed record CategoryRisk
{
    /// <summary>The finding category (e.g. PortScan, Beaconing).</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>Number of findings in this category.</summary>
    public int FindingCount { get; init; }

    /// <summary>Total risk deduction contributed by this category.</summary>
    public double TotalDeduction { get; init; }

    /// <summary>Average severity value for findings in this category.</summary>
    public double AverageSeverity { get; init; }
}
