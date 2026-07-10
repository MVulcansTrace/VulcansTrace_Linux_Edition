using System;
using System.Globalization;
using Avalonia.Data.Converters;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts internal category tokens (e.g. "FilesystemAudit") into human-readable
/// labels (e.g. "Filesystem Audit") for display. The raw value is unchanged.
/// </summary>
public sealed class CategoryLabelConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is string category
            ? CategoryDisplay.ToDisplayName(category)
            : value?.ToString();
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
