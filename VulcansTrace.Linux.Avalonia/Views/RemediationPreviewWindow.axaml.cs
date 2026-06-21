using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Dialog window for previewing and confirming schedule remediation.
/// </summary>
public partial class RemediationPreviewWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationPreviewWindow"/> class.
    /// </summary>
    public RemediationPreviewWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Initializes a new instance with the specified view model.
    /// </summary>
    public RemediationPreviewWindow(RemediationPreviewViewModel viewModel) : this()
    {
        DataContext = viewModel;
    }

    /// <summary>
    /// Gets the view model.
    /// </summary>
    public RemediationPreviewViewModel ViewModel => (RemediationPreviewViewModel)DataContext!;

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void CloseButton_Click(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}
