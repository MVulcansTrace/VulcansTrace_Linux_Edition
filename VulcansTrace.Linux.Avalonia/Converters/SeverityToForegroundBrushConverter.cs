using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a <see cref="Severity"/> value (or its string representation) to a foreground <see cref="IBrush"/>
/// for text displayed on dark-mode severity badges.
/// </summary>
public sealed class SeverityToForegroundBrushConverter : IValueConverter
{
    /// <summary>Gets or sets the brush to use for Critical severity text.</summary>
    public IBrush CriticalBrush { get; set; } = new SolidColorBrush(Color.Parse("#FFFFFF"));

    /// <summary>Gets or sets the brush to use for High severity text.</summary>
    public IBrush HighBrush { get; set; } = new SolidColorBrush(Color.Parse("#FFFFFF"));

    /// <summary>Gets or sets the brush to use for Medium severity text.</summary>
    public IBrush MediumBrush { get; set; } = new SolidColorBrush(Color.Parse("#0D1117"));

    /// <summary>Gets or sets the brush to use for Low severity text.</summary>
    public IBrush LowBrush { get; set; } = new SolidColorBrush(Color.Parse("#0D1117"));

    /// <summary>Gets or sets the brush to use for Info severity text.</summary>
    public IBrush InfoBrush { get; set; } = new SolidColorBrush(Color.Parse("#FFFFFF"));

    /// <summary>Gets or sets the fallback brush.</summary>
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#E6EDF3"));

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
