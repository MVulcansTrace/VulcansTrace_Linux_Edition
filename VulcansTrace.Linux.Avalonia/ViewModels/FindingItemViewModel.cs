using System;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel that adapts a <see cref="Finding"/> for UI display.
/// </summary>
public sealed class FindingItemViewModel
{
    /// <summary>Gets the finding category.</summary>
    public string Category { get; }

    /// <summary>Gets the severity label.</summary>
    public string Severity { get; }

    /// <summary>Gets the source host.</summary>
    public string SourceHost { get; }

    /// <summary>Gets the target host or resource.</summary>
    public string Target { get; }

    /// <summary>Gets the start time for the finding.</summary>
    public DateTime TimeStart { get; }

    /// <summary>Gets the end time for the finding.</summary>
    public DateTime TimeEnd { get; }

    /// <summary>Gets the short description for the finding.</summary>
    public string ShortDescription { get; }

    /// <summary>Gets the underlying finding.</summary>
    public Finding Finding { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="FindingItemViewModel"/> class.
    /// </summary>
    /// <param name="finding">The finding to display.</param>
    public FindingItemViewModel(Finding finding)
    {
        Finding = finding;
        Category = finding.Category;
        Severity = finding.Severity.ToString();
        SourceHost = finding.SourceHost;
        Target = finding.Target;
        TimeStart = finding.TimeRangeStart;
        TimeEnd = finding.TimeRangeEnd;
        ShortDescription = finding.ShortDescription;
    }
}
