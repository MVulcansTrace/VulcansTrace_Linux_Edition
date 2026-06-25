using System;
using System.Globalization;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a boolean to a horizontal alignment (Right for user, Left for agent).
/// </summary>
public sealed class BoolToAlignmentConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true ? global::Avalonia.Layout.HorizontalAlignment.Right : global::Avalonia.Layout.HorizontalAlignment.Left;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts a boolean to a background brush for agent messages.
/// </summary>
public sealed class BoolToBackgroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(Color.Parse("#2563eb"))
            : new SolidColorBrush(Color.Parse("#334155"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts a boolean to a border brush for agent messages.
/// </summary>
public sealed class BoolToBorderBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(Color.Parse("#1d4ed8"))
            : new SolidColorBrush(Color.Parse("#475569"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts a boolean to a foreground brush for agent messages.
/// </summary>
public sealed class BoolToForegroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true
            ? new SolidColorBrush(Color.Parse("#ffffff"))
            : new SolidColorBrush(Color.Parse("#e2e8f0"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts <see cref="TimelineGroupMode"/> to/from boolean for a ToggleButton.
/// True when mode is <see cref="TimelineGroupMode.Host"/>.
/// </summary>
public sealed class GroupModeToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is TimelineGroupMode.Host;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value is true ? TimelineGroupMode.Host : TimelineGroupMode.Category;
    }
}
