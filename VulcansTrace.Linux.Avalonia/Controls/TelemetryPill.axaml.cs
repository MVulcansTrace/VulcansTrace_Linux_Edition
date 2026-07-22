using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Compact horizontal metric pill for the top telemetry strip.
/// </summary>
public partial class TelemetryPill : UserControl
{
    public static readonly StyledProperty<string> IconProperty =
        AvaloniaProperty.Register<TelemetryPill, string>(nameof(Icon));

    public static readonly StyledProperty<string> LabelProperty =
        AvaloniaProperty.Register<TelemetryPill, string>(nameof(Label));

    public static readonly StyledProperty<object?> ValueProperty =
        AvaloniaProperty.Register<TelemetryPill, object?>(nameof(Value));

    public static readonly StyledProperty<IBrush?> AccentBrushProperty =
        AvaloniaProperty.Register<TelemetryPill, IBrush?>(nameof(AccentBrush));

    public static readonly StyledProperty<ICommand?> CommandProperty =
        AvaloniaProperty.Register<TelemetryPill, ICommand?>(nameof(Command));

    public static readonly StyledProperty<object?> CommandParameterProperty =
        AvaloniaProperty.Register<TelemetryPill, object?>(nameof(CommandParameter));

    public static readonly StyledProperty<string> PillAutomationIdProperty =
        AvaloniaProperty.Register<TelemetryPill, string>(nameof(PillAutomationId));

    public string Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    public string Label
    {
        get => GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public object? Value
    {
        get => GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    public IBrush? AccentBrush
    {
        get => GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    public ICommand? Command
    {
        get => GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }

    public object? CommandParameter
    {
        get => GetValue(CommandParameterProperty);
        set => SetValue(CommandParameterProperty, value);
    }

    public string PillAutomationId
    {
        get => GetValue(PillAutomationIdProperty);
        set => SetValue(PillAutomationIdProperty, value);
    }
}
