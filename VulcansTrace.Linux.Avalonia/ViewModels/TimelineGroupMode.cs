namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Determines how the timeline Y-axis is grouped.
/// </summary>
public enum TimelineGroupMode
{
    /// <summary>Group findings by their category (default timeline behavior).</summary>
    Category,

    /// <summary>Group findings by their source host (Trace Map mode).</summary>
    Host
}
