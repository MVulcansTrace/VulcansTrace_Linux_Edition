using System;
using System.Globalization;
using Avalonia.Data.Converters;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts suppression review filters into user-facing labels.
/// </summary>
public sealed class ReviewFilterLabelConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is ReviewFilter filter
            ? filter switch
            {
                ReviewFilter.AllNeedingReview => "All needing review",
                ReviewFilter.ExpiringSoon => "Expiring soon",
                ReviewFilter.ExpiredRecently => "Expired recently",
                ReviewFilter.Permanent => "Permanent",
                ReviewFilter.StalePermanent => "Stale permanent",
                _ => filter.ToString()
            }
            : value?.ToString();
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
