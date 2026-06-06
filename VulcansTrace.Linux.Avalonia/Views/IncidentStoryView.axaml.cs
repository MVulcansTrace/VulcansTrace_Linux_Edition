using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// View for the Incident Story tab.
/// </summary>
public partial class IncidentStoryView : UserControl
{
    public IncidentStoryView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
