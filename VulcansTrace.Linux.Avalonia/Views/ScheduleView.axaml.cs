using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// User control for managing recurring audit schedules.
/// </summary>
public partial class ScheduleView : UserControl
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ScheduleView"/> class.
    /// </summary>
    public ScheduleView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
