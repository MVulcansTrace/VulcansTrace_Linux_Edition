using System;
using System.Linq;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel that adapts a <see cref="RuleCatalogItem"/> for UI display.
/// </summary>
public sealed class RuleCatalogItemViewModel
{
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

    /// <summary>Gets the underlying catalog item.</summary>
    public RuleCatalogItem Item { get; }

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
    }
}
