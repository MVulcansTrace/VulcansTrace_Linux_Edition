using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a <see cref="LogDiffState"/> value to a foreground <see cref="IBrush"/> suitable for dark-mode UI.
/// </summary>
public sealed class LogDiffStateToForegroundBrushConverter : IValueConverter
{
    public IBrush AddedBrush { get; set; } = new SolidColorBrush(Color.Parse("#fecaca"));
    public IBrush RemovedBrush { get; set; } = new SolidColorBrush(Color.Parse("#bbf7d0"));
    public IBrush ChangedBrush { get; set; } = new SolidColorBrush(Color.Parse("#fde047"));
    public IBrush UnchangedBrush { get; set; } = new SolidColorBrush(Color.Parse("#94a3b8"));
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#cbd5e1"));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is LogDiffState state)
        {
            return state switch
            {
                LogDiffState.Added => AddedBrush,
                LogDiffState.Removed => RemovedBrush,
                LogDiffState.Changed => ChangedBrush,
                LogDiffState.Unchanged => UnchangedBrush,
                _ => FallbackBrush
            };
        }
        return FallbackBrush;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
