using System;
using System.Collections.Concurrent;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
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
        if (targetType == typeof(global::Avalonia.Media.TextAlignment))
        {
            return value is true ? global::Avalonia.Media.TextAlignment.Right : global::Avalonia.Media.TextAlignment.Left;
        }
        return value is true ? global::Avalonia.Layout.HorizontalAlignment.Right : global::Avalonia.Layout.HorizontalAlignment.Left;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts a boolean to a double, using configurable values for true/false.
/// Useful for animating MaxHeight or Opacity based on a view-model flag.
/// </summary>
public sealed class BoolToDoubleConverter : IValueConverter
{
    public double TrueValue { get; set; } = 1.0;
    public double FalseValue { get; set; } = 0.0;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? TrueValue : FalseValue;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is double d && d.Equals(TrueValue);
}

/// <summary>
/// Converts <see cref="TimelineGroupMode"/u003e to/from boolean for a ToggleButton.
/// True when mode is <see cref="TimelineGroupMode.Host"/u003e.
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

/// <summary>
/// Converts an agent status string to a background brush for the header badge.
/// </summary>
public sealed class AgentStatusToBackgroundBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value?.ToString()?.ToLowerInvariant() switch
        {
            "busy" => ThemeBrush.Get("VtAgentStatusBusyBackgroundBrush", Color.Parse("#713f12")), // warning muted
            _ => ThemeBrush.Get("VtAgentStatusOnlineBackgroundBrush", Color.Parse("#064e3b")) // success muted (Online)
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts an agent status string to a foreground brush for the header badge.
/// </summary>
public sealed class AgentStatusToForegroundBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value?.ToString()?.ToLowerInvariant() switch
        {
            "busy" => ThemeBrush.Get("VtAgentStatusBusyForegroundBrush", Color.Parse("#facc15")), // warning
            _ => ThemeBrush.Get("VtAgentStatusOnlineForegroundBrush", Color.Parse("#4ade80")) // success (Online)
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts an <see cref="AgentMessageViewModel"/> to a message bubble background brush,
/// taking both the user/agent role and the error state into account.
/// </summary>
public sealed class MessageBubbleBackgroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is AgentMessageViewModel { IsError: true })
            return ThemeBrush.Get("VtErrorBubbleBackgroundBrush", Color.Parse("#450A0A"));

        return value is AgentMessageViewModel { IsUser: true }
            ? ThemeBrush.Get("VtUserBubbleBackgroundBrush", Color.Parse("#2563eb"))
            : ThemeBrush.Get("VtAgentBubbleBackgroundBrush", Color.Parse("#334155"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts an <see cref="AgentMessageViewModel"/> to a message bubble border brush,
/// taking both the user/agent role and the error state into account.
/// </summary>
public sealed class MessageBubbleBorderBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is AgentMessageViewModel { IsError: true })
            return ThemeBrush.Get("VtErrorBubbleBorderBrush", Color.Parse("#EF4444"));

        return value is AgentMessageViewModel { IsUser: true }
            ? ThemeBrush.Get("VtUserBubbleBorderBrush", Color.Parse("#1d4ed8"))
            : ThemeBrush.Get("VtAgentBubbleBorderBrush", Color.Parse("#475569"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Converts an <see cref="AgentMessageViewModel"/> to a message bubble foreground brush,
/// taking both the user/agent role and the error state into account.
/// </summary>
public sealed class MessageBubbleForegroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is AgentMessageViewModel { IsError: true })
            return ThemeBrush.Get("VtErrorBubbleForegroundBrush", Color.Parse("#F8FAFC"));

        return value is AgentMessageViewModel { IsUser: true }
            ? ThemeBrush.Get("VtUserBubbleForegroundBrush", Color.Parse("#ffffff"))
            : ThemeBrush.Get("VtAgentBubbleForegroundBrush", Color.Parse("#e2e8f0"));
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}

/// <summary>
/// Looks up design-token brushes from application resources without caching them,
/// so a runtime theme change is reflected immediately. Caches only fallback
/// <see cref="SolidColorBrush"/> instances by color to avoid allocating on every binding update.
/// Falls back to the supplied color when the application or resource is not available.
/// </summary>
public static class ThemeBrush
{
    private static readonly ConcurrentDictionary<Color, IBrush> FallbackCache = new();

    public static IBrush Get(string key, Color fallback)
    {
        if (Application.Current?.TryFindResource(key, null, out var resource) == true && resource is IBrush brush)
        {
            return brush;
        }

        return FallbackCache.GetOrAdd(fallback, c => new SolidColorBrush(c));
    }

    /// <summary>
    /// Clears the fallback-color cache. Useful in tests or after a theme switch
    /// if the cached fallback colors should be rebuilt.
    /// </summary>
    public static void ClearFallbackCache() => FallbackCache.Clear();
}
