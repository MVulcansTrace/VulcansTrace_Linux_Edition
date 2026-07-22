using Avalonia.Controls;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Displays the running-state scan progress: progress bar, phase checklist,
/// current activity, elapsed time, and cancel button.
/// </summary>
public partial class ScanProgressView : UserControl
{
    public ScanProgressView()
    {
        InitializeComponent();
    }
}
