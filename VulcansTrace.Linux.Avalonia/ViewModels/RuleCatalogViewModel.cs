using System;
using System.Collections.ObjectModel;
using System.Linq;
using VulcansTrace.Linux.Agent.Rules;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying and searching the rule catalog.
/// </summary>
public sealed class RuleCatalogViewModel : ViewModelBase
{
    private string _searchText = "";
    private int _totalRules;

    /// <summary>Gets the collection of all catalog items.</summary>
    public ObservableCollection<RuleCatalogItemViewModel> Items { get; } = new();

    /// <summary>Gets the filtered view of catalog items.</summary>
    public ObservableCollection<RuleCatalogItemViewModel> FilteredItems { get; } = new();

    /// <summary>Gets or sets the search text for filtering rules.</summary>
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
            {
                ApplyFilters();
            }
        }
    }

    /// <summary>Gets the total number of rules in the catalog.</summary>
    public int TotalRules
    {
        get => _totalRules;
        private set => SetField(ref _totalRules, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RuleCatalogViewModel"/> class.
    /// </summary>
    public RuleCatalogViewModel()
    {
    }

    /// <summary>
    /// Loads rules from a <see cref="RuleCatalog"/>.
    /// </summary>
    /// <param name="catalog">The rule catalog to load.</param>
    public void LoadCatalog(RuleCatalog catalog)
    {
        Items.Clear();
        FilteredItems.Clear();

        foreach (var item in catalog.Items)
        {
            Items.Add(new RuleCatalogItemViewModel(item));
        }

        TotalRules = Items.Count;
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        FilteredItems.Clear();

        var term = _searchText?.Trim();
        if (string.IsNullOrWhiteSpace(term))
        {
            foreach (var item in Items)
            {
                FilteredItems.Add(item);
            }
            return;
        }

        foreach (var item in Items)
        {
            if (item.Id.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.Category.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.Description.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.WhatItChecks.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.DataSources.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                item.MitreTechniquesDisplay.Contains(term, StringComparison.OrdinalIgnoreCase))
            {
                FilteredItems.Add(item);
            }
        }
    }
}
