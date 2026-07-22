using System;
using System.Globalization;
using Avalonia.Data.Converters;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Builds a screen-reader-friendly label for a <see cref="TimelineEntry"/> so each row of
/// the accessible companion list (UI v2 Phase 4) announces severity, category, endpoints and
/// time. The canvas markers these mirror are drawn in code-behind and carry no automation
/// peer, so this label is the machine-readable identity of the event.
/// </summary>
public sealed class TimelineEntryLabelConverter : IValueConverter
{
    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not TimelineEntry entry)
        {
            return value?.ToString();
        }

        var category = CategoryDisplay.ToDisplayName(entry.Category);
        var host = string.IsNullOrWhiteSpace(entry.SourceHost) ? "unknown host" : entry.SourceHost;
        var target = string.IsNullOrWhiteSpace(entry.Target) ? "unknown target" : entry.Target;
        return $"{entry.Severity} {category} finding: {host} to {target}, {entry.FormattedTimeRange}";
    }

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
