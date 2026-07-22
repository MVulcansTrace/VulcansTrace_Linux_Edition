using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// "N more findings — open Findings view" deep link posted to the agent thread after
/// the per-finding cards (UI v2 Phase 2). Shown only when the finding count exceeds
/// the inline card limit.
/// </summary>
public sealed class MoreFindingsLinkMessageViewModel : AgentMessageViewModel
{
    /// <summary>Gets the number of findings not shown as inline cards.</summary>
    public required int RemainingCount { get; init; }

    /// <summary>Gets the link text.</summary>
    public string LinkText => $"{RemainingCount} more findings — open Findings view";

    /// <summary>Gets the deep-link command (the KPI navigate command).</summary>
    public ICommand? OpenCommand { get; init; }

    /// <summary>Gets the parameter passed to <see cref="OpenCommand"/> ("findings").</summary>
    public object? CommandParameter { get; init; }
}
