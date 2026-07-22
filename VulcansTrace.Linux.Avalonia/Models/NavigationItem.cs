using System;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.Models;

/// <summary>
/// Represents a single item in the sidebar navigation.
/// </summary>
public sealed class NavigationItem
{
    /// <summary>Display label for the navigation item.</summary>
    public string Label { get; set; } = "";

    /// <summary>Material Design icon name, e.g. "mdi-magnify".</summary>
    public string Icon { get; set; } = "";

    /// <summary>The ViewModel instance to display when this item is selected.</summary>
    public object? Content { get; set; }

    /// <summary>Group name for categorization (Analysis, Management, Operations, System).</summary>
    public string Group { get; set; } = "";

    /// <summary>Whether this item is currently selected.</summary>
    public bool IsSelected { get; set; }

    /// <summary>
    /// Command that selects this item. Used by the icon-rail flyouts (UI v2
    /// Phase 3): popup DataContexts cannot reach the window's MainViewModel,
    /// so the item carries its own navigation command.
    /// </summary>
    public ICommand? NavigateCommand { get; set; }
}
