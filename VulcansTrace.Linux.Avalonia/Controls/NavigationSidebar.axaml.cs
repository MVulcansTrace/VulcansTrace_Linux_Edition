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

}
