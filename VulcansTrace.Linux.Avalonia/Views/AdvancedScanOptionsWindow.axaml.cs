using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Dialog hosting the advanced detector numerics and the session HMAC info
/// (UI v2 Phase 2). Opened from the hero scan-options "Advanced..." button;
/// DataContext is the MainViewModel, set by the caller.
/// </summary>
public partial class AdvancedScanOptionsWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AdvancedScanOptionsWindow"/> class.
    /// </summary>
    public AdvancedScanOptionsWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void CloseButton_Click(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}
