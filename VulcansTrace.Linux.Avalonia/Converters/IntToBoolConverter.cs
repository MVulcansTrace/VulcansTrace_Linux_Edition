using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts an integer to a boolean (true if greater than zero).
/// </summary>
public sealed class IntToBoolConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is int count)
            return count > 0;
        return false;
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
