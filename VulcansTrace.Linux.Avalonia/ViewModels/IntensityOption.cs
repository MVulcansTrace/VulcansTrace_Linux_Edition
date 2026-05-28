using VulcansTrace.Linux.Engine;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Represents an analysis intensity option for the UI.
/// </summary>
/// <remarks>
/// Data transfer object for binding intensity levels to UI dropdown lists.
/// </remarks>
public sealed class IntensityOption
{
    /// <summary>
    /// Gets the display text for this intensity option.
    /// </summary>
    public string Display { get; }

    /// <summary>
    /// Gets the underlying intensity level value.
    /// </summary>
    public IntensityLevel Level { get; }

    /// <summary>
    /// Initializes a new instance of the IntensityOption class.
    /// </summary>
    /// <param name="display">The display text to show in the UI.</param>
    /// <param name="level">The intensity level value.</param>
    public IntensityOption(string display, IntensityLevel level)
    {
        Display = display;
        Level = level;
    }

    /// <summary>
    /// Returns the display text for this option.
    /// </summary>
    /// <returns>The display text.</returns>
    public override string ToString() => Display;
}