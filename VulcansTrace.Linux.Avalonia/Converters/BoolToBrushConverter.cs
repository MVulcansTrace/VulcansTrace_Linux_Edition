using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a <see cref="bool"/> value to a <see cref="IBrush"/>. Used for
/// status text whose color must track success vs. failure (e.g. a copy-status
/// message that is green on success and red on error). Settable brush
/// properties follow the convention of <see cref="LogDiffStateToBrushConverter"/>
/// and <see cref="SeverityToBrushConverter"/>.
/// </summary>
public sealed class BoolToBrushConverter : IValueConverter
{
    /// <summary>Brush used when the bound value is <c>true</c>.</summary>
    public IBrush? TrueBrush { get; set; }

    /// <summary>Brush used when the bound value is <c>false</c>.</summary>
    public IBrush? FalseBrush { get; set; }

    /// <summary>Brush used when the bound value is not a <see cref="bool"/>.</summary>
    public IBrush? FallbackBrush { get; set; }

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return b ? TrueBrush : FalseBrush;
        }
        return FallbackBrush;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
