using System;
using System.Globalization;
using Avalonia.Data.Converters;
using VulcansTrace.Linux.Agent.Notifications;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a <see cref="NotificationChannel"/> to a human-readable label.
/// </summary>
public sealed class NotificationChannelLabelConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is NotificationChannel channel)
        {
            return channel.GetLabel();
        }

        return value?.ToString();
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
