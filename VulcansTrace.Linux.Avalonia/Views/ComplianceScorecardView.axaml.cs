using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Code-behind for the Compliance Scorecard view.
/// </summary>
public partial class ComplianceScorecardView : UserControl
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ComplianceScorecardView"/> class.
    /// </summary>
    public ComplianceScorecardView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
