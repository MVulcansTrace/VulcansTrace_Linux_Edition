using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.VisualTree;
using VulcansTrace.Linux.Avalonia.Models;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Vertical sidebar navigation with icon + label items.
/// </summary>
public partial class NavigationSidebar : UserControl
{
    /// <summary>Creates a new NavigationSidebar.</summary>
    public NavigationSidebar()
    {
        InitializeComponent();
    }

    private void OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (NavListBox?.SelectedItem is not NavigationItem item)
            return;

        if (DataContext is MainViewModel vm)
            vm.SelectedNavigationItem = item;
    }
}
