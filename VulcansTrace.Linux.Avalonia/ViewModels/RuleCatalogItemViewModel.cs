using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel that adapts a <see cref="RuleCatalogItem"/> for UI display.
/// </summary>
public sealed class RuleCatalogItemViewModel : ViewModelBase
{
    private string _policyOverrideDisplay = "";
    /// <summary>Gets the rule identifier.</summary>
    public string Id { get; }

    /// <summary>Gets the rule category.</summary>
    public string Category { get; }

    /// <summary>Gets the brief description.</summary>
    public string Description { get; }

    /// <summary>Gets the detailed description of what it checks.</summary>
    public string WhatItChecks { get; }

    /// <summary>Gets the severity label.</summary>
    public string Severity { get; }

    /// <summary>Gets the severity enum value.</summary>
    public Severity SeverityValue { get; }

    /// <summary>Gets the supported data sources as a comma-separated string.</summary>
    public string DataSources { get; }

    /// <summary>Gets the formatted MITRE ATT&CK technique IDs for display.</summary>
    public string MitreTechniquesDisplay { get; }

    /// <summary>Gets the underlying catalog item.</summary>
    public RuleCatalogItem Item { get; }

    /// <summary>
    /// Gets or sets a short summary of the per-role override applied to this rule for the active
    /// machine role (e.g. "Disabled", "Sev: High"), or empty when no override is in effect.
    /// </summary>
    public string PolicyOverrideDisplay
    {
        get => _policyOverrideDisplay;
        set => SetField(ref _policyOverrideDisplay, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RuleCatalogItemViewModel"/> class.
    /// </summary>
    /// <param name="item">The catalog item to display.</param>
    public RuleCatalogItemViewModel(RuleCatalogItem item)
    {
        Item = item;
        Id = item.Id;
        Category = item.Category;
        Description = item.Description;
        WhatItChecks = item.WhatItChecks;
        Severity = item.Severity.ToString();
        SeverityValue = item.Severity;
        DataSources = string.Join(", ", item.SupportedDataSources);
        MitreTechniquesDisplay = FormatMitreTechniques(item.MitreTechniques);
    }

    private static string FormatMitreTechniques(IReadOnlyList<MitreTechnique> techniques)
    {
        if (techniques.Count == 0)
            return string.Empty;
        return string.Join(", ", techniques.Select(t => $"{t.TechniqueId}"));
    }
}
