using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Code-behind for the Risk Scorecard view.
/// </summary>
public partial class RiskScorecardView : UserControl
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RiskScorecardView"/> class.
    /// </summary>
    public RiskScorecardView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
