using Avalonia.Controls;
using Avalonia.Interactivity;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Window for displaying a log diff result.
/// </summary>
public partial class LogDiffWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LogDiffWindow"/> class.
    /// </summary>
    public LogDiffWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Initializes the window with the specified view model.
    /// </summary>
    /// <param name="viewModel">The view model containing the diff data.</param>
    public LogDiffWindow(LogDiffViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

    private void CloseButton_Click(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}
