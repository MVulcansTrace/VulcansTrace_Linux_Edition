using System;
using System.Collections.ObjectModel;
using System.ComponentModel;

namespace VulcansTrace.Linux.Avalonia.Models;

/// <summary>
/// A collapsible group of sidebar navigation items (e.g. ANALYSIS).
/// The flat <see cref="NavigationItem"/> list remains the canonical model
/// (selection, lookups); groups are a presentation projection.
/// </summary>
public sealed class NavigationGroup : INotifyPropertyChanged
{
    private bool _isExpanded = true;
    private bool _isActive;

    /// <summary>Display name in caps (e.g. "ANALYSIS").</summary>
    public required string Name { get; init; }

    /// <summary>Items in display order (same instances as the flat list).</summary>
    public ObservableCollection<NavigationItem> Items { get; } = new();

    /// <summary>Automation id for the group's expand/collapse toggle.</summary>
    public string ToggleAutomationId => $"NavGroup{TitleName}Toggle";

    /// <summary>Accessible name for the group's expand/collapse toggle.</summary>
    public string ToggleAccessibleName => $"{TitleName} navigation group";

    /// <summary>Automation id for the group's item list.</summary>
    public string ListAutomationId => $"NavGroup{TitleName}List";

    /// <summary>Automation id for the group's icon-rail button (collapsed sidebar).</summary>
    public string RailAutomationId => $"NavGroup{TitleName}RailButton";

    /// <summary>Icon for the group's icon-rail button (collapsed sidebar).</summary>
    public string RailIcon => Name switch
    {
        "ANALYSIS" => "mdi-magnify",
        "MANAGEMENT" => "mdi-shield-check-outline",
        "OPERATIONS" => "mdi-cog-outline",
        "SYSTEM" => "mdi-information-outline",
        _ => "mdi-dots-horizontal"
    };

    /// <summary>Whether the group's items are visible. Expanded by default.</summary>
    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (_isExpanded != value)
            {
                _isExpanded = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
            }
        }
    }

    /// <summary>True when this group contains the currently selected nav item;
    /// drives the icon-rail active indicator (collapsed sidebar).</summary>
    public bool IsActive
    {
        get => _isActive;
        set
        {
            if (_isActive != value)
            {
                _isActive = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsActive)));
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private string TitleName =>
        string.Concat(Name[..1].ToUpperInvariant(), Name[1..].ToLowerInvariant());
}
