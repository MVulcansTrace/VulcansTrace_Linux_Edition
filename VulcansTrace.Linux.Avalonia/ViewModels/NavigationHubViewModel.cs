using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using VulcansTrace.Linux.Avalonia.Models;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Groups related capability views behind one product-level destination.
/// </summary>
public sealed class NavigationHubViewModel : ViewModelBase
{
    private NavigationHubSection _selectedSection;

    /// <summary>Initializes a navigation hub.</summary>
    public NavigationHubViewModel(
        string title,
        string description,
        IEnumerable<NavigationHubSection> sections)
    {
        Title = title;
        Description = description;
        Sections = new ObservableCollection<NavigationHubSection>(sections);
        _selectedSection = Sections.FirstOrDefault()
            ?? throw new ArgumentException("A navigation hub requires at least one section.", nameof(sections));
    }

    /// <summary>Gets the product-level destination title.</summary>
    public string Title { get; }

    /// <summary>Gets the short purpose statement displayed under the title.</summary>
    public string Description { get; }

    /// <summary>Gets the capability sections available inside the hub.</summary>
    public ObservableCollection<NavigationHubSection> Sections { get; }

    /// <summary>Gets or sets the active capability section.</summary>
    public NavigationHubSection SelectedSection
    {
        get => _selectedSection;
        set
        {
            if (value != null && SetField(ref _selectedSection, value))
            {
                OnPropertyChanged(nameof(ActiveSectionLabel));
            }
        }
    }

    /// <summary>Gets the active leaf label used by status and automation surfaces.</summary>
    public string ActiveSectionLabel => SelectedSection.Label;

    /// <summary>Selects a section by label, returning whether it was found.</summary>
    public bool SelectSection(string label)
    {
        var section = Sections.FirstOrDefault(candidate =>
            string.Equals(candidate.Label, label, StringComparison.OrdinalIgnoreCase));
        if (section == null)
            return false;

        SelectedSection = section;
        return true;
    }
}
