using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Code-behind for the agent chat panel view.
/// </summary>
public partial class AgentView : UserControl
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgentView"/> class.
    /// </summary>
    public AgentView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    /// <summary>
    /// Copies the command text from the clicked button's Tag to the clipboard.
    /// </summary>
    private void OnCopyCommandClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is string commandText)
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow?.Clipboard?.SetTextAsync(commandText);
            }
        }
    }
}
