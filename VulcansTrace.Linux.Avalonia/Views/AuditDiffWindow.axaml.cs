using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// A window that displays the diff between two agent audits.
/// </summary>
public partial class AuditDiffWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditDiffWindow"/> class.
    /// </summary>
    public AuditDiffWindow()
    {
        InitializeComponent();
        DataContext = new AuditDiffViewModel();
    }

    /// <summary>
    /// Gets the view model.
    /// </summary>
    public AuditDiffViewModel ViewModel => (AuditDiffViewModel)DataContext!;

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
