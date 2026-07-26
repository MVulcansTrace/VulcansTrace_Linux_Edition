using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Renders a <see cref="DateTime"/> as <c>yyyy-MM-dd HH:mm:ss</c>, or an em dash when the value is
/// <see cref="DateTime.MinValue"/> (or null/unset). Used by the log-diff grid where Added events have
/// no baseline first-seen and Removed events have no incident first-seen — previously the sentinel
/// <c>0001-01-01 00:00:00</c> leaked through to the UI.
/// </summary>
public sealed class DateTimeMinValueToTextConverter : IValueConverter
{
    private const string Format = "yyyy-MM-dd HH:mm:ss";
    private const string Placeholder = "—";

    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is null)
            return Placeholder;

        if (value is DateTime dt)
            return dt == DateTime.MinValue ? Placeholder : dt.ToString(Format, culture);

        if (value is DateTimeOffset dto)
            return dto == DateTimeOffset.MinValue ? Placeholder : dto.ToString(Format, culture);

        return Placeholder;
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
