using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Code-behind for the Doctor diagnostic view.
/// </summary>
public partial class DoctorView : UserControl
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DoctorView"/> class.
    /// </summary>
    public DoctorView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
