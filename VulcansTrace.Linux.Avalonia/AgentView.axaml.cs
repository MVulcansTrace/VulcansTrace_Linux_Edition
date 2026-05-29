using Avalonia.Controls;
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
}
