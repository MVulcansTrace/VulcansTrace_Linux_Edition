using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a compliance status string (Pass, Warn, Fail) to a background brush for dark-mode UI.
/// </summary>
public sealed class ComplianceStatusToBackgroundConverter : IValueConverter
{
    public IBrush PassBrush { get; set; } = new SolidColorBrush(Color.Parse("#064e3b"));
    public IBrush WarnBrush { get; set; } = new SolidColorBrush(Color.Parse("#451a03"));
    public IBrush FailBrush { get; set; } = new SolidColorBrush(Color.Parse("#450a0a"));
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#1e293b"));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var status = value?.ToString();
        return status switch
        {
            "Pass" => PassBrush,
            "Warn" => WarnBrush,
            "Fail" => FailBrush,
            _ => FallbackBrush
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts a compliance status string (Pass, Warn, Fail) to a foreground brush for dark-mode UI.
/// </summary>
public sealed class ComplianceStatusToForegroundConverter : IValueConverter
{
    public IBrush PassBrush { get; set; } = new SolidColorBrush(Color.Parse("#34d399"));
    public IBrush WarnBrush { get; set; } = new SolidColorBrush(Color.Parse("#fbbf24"));
    public IBrush FailBrush { get; set; } = new SolidColorBrush(Color.Parse("#f87171"));
    public IBrush FallbackBrush { get; set; } = new SolidColorBrush(Color.Parse("#94a3b8"));

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var status = value?.ToString();
        return status switch
        {
            "Pass" => PassBrush,
            "Warn" => WarnBrush,
            "Fail" => FailBrush,
            _ => FallbackBrush
        };
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
