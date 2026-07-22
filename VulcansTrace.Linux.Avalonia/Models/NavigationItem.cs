using System;
using System.ComponentModel;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.Models;

/// <summary>
/// Represents a single item in the sidebar navigation.
/// </summary>
public sealed class NavigationItem : INotifyPropertyChanged
{
    private bool _isSelected;

    /// <summary>Display label for the navigation item.</summary>
    public string Label { get; set; } = "";

    /// <summary>Material Design icon name, e.g. "mdi-magnify".</summary>
    public string Icon { get; set; } = "";

    /// <summary>The ViewModel instance to display when this item is selected.</summary>
    public object? Content { get; set; }

    /// <summary>Legacy group name retained for persisted and test compatibility.</summary>
    public string Group { get; set; } = "";

    /// <summary>Whether this item is currently selected.</summary>
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
            }
        }
    }

    /// <summary>Stable automation id for the top-level destination.</summary>
    public string AutomationId { get; set; } = "";

    /// <summary>
    /// Command that selects this item. Used by the icon-rail flyouts (UI v2
    /// Phase 3): popup DataContexts cannot reach the window's MainViewModel,
    /// so the item carries its own navigation command.
    /// </summary>
    public ICommand? NavigateCommand { get; set; }

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;
}
