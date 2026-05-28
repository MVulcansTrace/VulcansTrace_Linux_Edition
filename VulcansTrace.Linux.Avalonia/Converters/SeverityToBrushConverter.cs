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
    public IBrush CriticalBrush { get; set; } = new SolidColorBrush(Color.Parse("#7f1d1d"));

    /// <summary>Gets or sets the brush to use for High severity.</summary>
    public IBrush HighBrush { get; set; } = new SolidColorBrush(Color.Parse("#7c2d12"));

    /// <summary>Gets or sets the brush to use for Medium severity.</summary>
    public IBrush MediumBrush { get; set; } = new SolidColorBrush(Color.Parse("#713f12"));

    /// <summary>Gets or sets the brush to use for Low severity.</summary>
    public IBrush LowBrush { get; set; } = new SolidColorBrush(Color.Parse("#14532d"));

    /// <summary>Gets or sets the brush to use for Info severity.</summary>
    public IBrush InfoBrush { get; set; } = new SolidColorBrush(Color.Parse("#1e293b"));

    /// <summary>Gets or sets the fallback brush.</summary>
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#334155"));

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
