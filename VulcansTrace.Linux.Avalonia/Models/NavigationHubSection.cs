namespace VulcansTrace.Linux.Avalonia.Models;

/// <summary>
/// Describes one capability surface inside a top-level navigation hub.
/// </summary>
public sealed class NavigationHubSection
{
    /// <summary>Gets the section label shown in the hub tab strip.</summary>
    public required string Label { get; init; }

    /// <summary>Gets the Material Design icon used by the section tab.</summary>
    public required string Icon { get; init; }

    /// <summary>Gets the existing view model rendered for the section.</summary>
    public required object Content { get; init; }
}
