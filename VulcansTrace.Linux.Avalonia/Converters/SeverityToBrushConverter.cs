using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a <see cref="Severity"/> value (or its string representation) to a <see cref="IBrush"/>
/// suitable for dark-mode UI backgrounds.
/// </summary>
public sealed class SeverityToBrushConverter : IValueConverter
{
    /// <summary>Gets or sets the brush to use for Critical severity.</summary>
    public IBrush CriticalBrush { get; set; } = new SolidColorBrush(Color.Parse("#F85149"));

    /// <summary>Gets or sets the brush to use for High severity.</summary>
    public IBrush HighBrush { get; set; } = new SolidColorBrush(Color.Parse("#F0883E"));

    /// <summary>Gets or sets the brush to use for Medium severity.</summary>
    public IBrush MediumBrush { get; set; } = new SolidColorBrush(Color.Parse("#D29922"));

    /// <summary>Gets or sets the brush to use for Low severity.</summary>
    public IBrush LowBrush { get; set; } = new SolidColorBrush(Color.Parse("#3FB950"));

    /// <summary>Gets or sets the brush to use for Info severity.</summary>
    public IBrush InfoBrush { get; set; } = new SolidColorBrush(Color.Parse("#58A6FF"));

    /// <summary>Gets or sets the fallback brush.</summary>
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#6E7681"));

    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var severityStr = value?.ToString();
        if (Enum.TryParse<Severity>(severityStr, out var severity))
        {
            return severity switch
            {
                Severity.Critical => CriticalBrush,
                Severity.High => HighBrush,
                Severity.Medium => MediumBrush,
                Severity.Low => LowBrush,
                Severity.Info => InfoBrush,
                _ => FallbackBrush
            };
        }
        return FallbackBrush;
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
