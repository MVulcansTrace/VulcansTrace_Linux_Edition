using Avalonia.Data.Converters;
using Avalonia.Media;
using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts CommandSafety values to background brushes for UI badges.
/// </summary>
public sealed class CommandSafetyToBrushConverter : IValueConverter
{
    /// <summary>Shared instance of the converter.</summary>
    public static readonly CommandSafetyToBrushConverter Instance = new();

    /// <inheritdoc />
    public object? Convert(object? value, System.Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        if (value is CommandSafety safety)
        {
            return safety switch
            {
                CommandSafety.ReadOnly => new SolidColorBrush(Color.Parse("#1e3a2f")),
                CommandSafety.ConfigChange => new SolidColorBrush(Color.Parse("#3f2e14")),
                CommandSafety.PackageInstall => new SolidColorBrush(Color.Parse("#2e1065")),
                CommandSafety.ServiceRestart => new SolidColorBrush(Color.Parse("#1e3a5f")),
                CommandSafety.Destructive => new SolidColorBrush(Color.Parse("#450a0a")),
                _ => new SolidColorBrush(Color.Parse("#1e293b"))
            };
        }
        return new SolidColorBrush(Color.Parse("#1e293b"));
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, System.Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        throw new System.NotSupportedException();
    }
}

/// <summary>
/// Converts CommandSafety values to foreground brushes for UI badges.
/// </summary>
public sealed class CommandSafetyToForegroundConverter : IValueConverter
{
    /// <summary>Shared instance of the converter.</summary>
    public static readonly CommandSafetyToForegroundConverter Instance = new();

    /// <inheritdoc />
    public object? Convert(object? value, System.Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        if (value is CommandSafety safety)
        {
            return safety switch
            {
                CommandSafety.ReadOnly => new SolidColorBrush(Color.Parse("#4ade80")),
                CommandSafety.ConfigChange => new SolidColorBrush(Color.Parse("#fcd34d")),
                CommandSafety.PackageInstall => new SolidColorBrush(Color.Parse("#c084fc")),
                CommandSafety.ServiceRestart => new SolidColorBrush(Color.Parse("#60a5fa")),
                CommandSafety.Destructive => new SolidColorBrush(Color.Parse("#f87171")),
                _ => new SolidColorBrush(Color.Parse("#94a3b8"))
            };
        }
        return new SolidColorBrush(Color.Parse("#94a3b8"));
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, System.Type targetType, object? parameter, System.Globalization.CultureInfo culture)
    {
        throw new System.NotSupportedException();
    }
}
