using System.Linq;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A single quick-check action shown as a chip above the agent input.
/// </summary>
public sealed class AgentQuickAction
{
    public string Label { get; set; } = "";
    public string Icon { get; set; } = "";
    public string Group { get; set; } = "";
    public ICommand Command { get; set; } = new RelayCommand(_ => { });

    /// <summary>
    /// Gets or sets an explicit automation identifier. When set, it overrides the derived value.
    /// </summary>
    public string? AutomationIdOverride { get; set; }

    /// <summary>
    /// Gets a stable identifier for this quick action, suitable for automation tests.
    /// Derived from the group and label by removing spaces and special characters, unless
    /// <see cref="AutomationIdOverride"/> is set.
    /// </summary>
    public string AutomationId => AutomationIdOverride ?? $"AgentQuickAction_{Sanitize(Group)}_{Sanitize(Label)}";

    private static string Sanitize(string value) => new string(value.Where(char.IsLetterOrDigit).ToArray());
}
