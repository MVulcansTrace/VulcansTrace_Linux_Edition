using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class CommandRow : UserControl
{
    public CommandRow()
    {
        InitializeComponent();
    }

    private void OnCopyClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is CopyableCommand command && Application.Current?.ApplicationLifetime is global::Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow?.Clipboard?.SetTextAsync(command.FullCommand);
        }
    }
}
