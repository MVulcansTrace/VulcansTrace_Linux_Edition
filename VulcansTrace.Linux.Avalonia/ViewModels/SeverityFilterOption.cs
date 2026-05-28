using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Represents a severity filter option for the UI.
/// </summary>
public sealed class SeverityFilterOption
{
    /// <summary>Gets the display text for this filter option.</summary>
    public string Display { get; }

    /// <summary>Gets the minimum severity for the filter, or null for all severities.</summary>
    public Severity? MinSeverity { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SeverityFilterOption"/> class.
    /// </summary>
    /// <param name="display">The display text to show in the UI.</param>
    /// <param name="minSeverity">The minimum severity threshold, or null for all.</param>
    public SeverityFilterOption(string display, Severity? minSeverity)
    {
        Display = display;
        MinSeverity = minSeverity;
    }

    /// <summary>
    /// Returns the display text for this option.
    /// </summary>
    /// <returns>The display text.</returns>
    public override string ToString() => Display;
}
