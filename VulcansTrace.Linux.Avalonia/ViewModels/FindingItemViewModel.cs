using System;
using System.Collections.Generic;
using System.Linq;
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

    /// <summary>Gets the confidence label.</summary>
    public string Confidence { get; }

    /// <summary>Gets the formatted evidence signals for display.</summary>
    public string EvidenceSignalsDisplay { get; }

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

    /// <summary>Gets the formatted MITRE ATT&CK technique IDs for display.</summary>
    public string MitreTechniquesDisplay { get; }

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
        Confidence = finding.Confidence.ToString();
        EvidenceSignalsDisplay = FormatEvidenceSignals(finding.EvidenceSignals);
        SourceHost = finding.SourceHost;
        Target = finding.Target;
        TimeStart = finding.TimeRangeStart;
        TimeEnd = finding.TimeRangeEnd;
        ShortDescription = finding.ShortDescription;
        MitreTechniquesDisplay = FormatMitreTechniques(finding.MitreTechniques);
    }

    private static string FormatMitreTechniques(IReadOnlyList<MitreTechnique> techniques)
    {
        if (techniques.Count == 0)
            return string.Empty;
        return string.Join(", ", techniques.Select(t => $"{t.TechniqueId}"));
    }

    private static string FormatEvidenceSignals(IReadOnlyList<EvidenceSignal> signals)
    {
        if (signals.Count == 0)
            return string.Empty;
        return string.Join(", ", signals.Select(s => s.Name));
    }
}
