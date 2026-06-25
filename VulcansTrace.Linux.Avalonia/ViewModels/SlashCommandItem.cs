using System;
using System.Threading.Tasks;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A single slash-command entry shown in the command palette.
/// </summary>
public sealed class SlashCommandItem
{
    public string CommandText { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public ICommand? Command { get; set; }

    /// <summary>
    /// Optional async handler invoked when the user selects this command.
    /// Used when the command should bypass the normal query pipeline.
    /// </summary>
    public Func<Task>? Handler { get; set; }
}
