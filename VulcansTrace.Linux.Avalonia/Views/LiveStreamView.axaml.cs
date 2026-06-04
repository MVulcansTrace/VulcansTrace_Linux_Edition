using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Code-behind for the Live Stream view.
/// </summary>
public partial class LiveStreamView : UserControl
{
    public LiveStreamView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
