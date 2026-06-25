using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A single quick-check action shown as a chip above the agent input.
/// </summary>
public sealed class AgentQuickAction
{
    public string Label { get; set; } = "";
    public string Icon { get; set; } = "";
    public ICommand Command { get; set; } = new RelayCommand(_ => { });
}
