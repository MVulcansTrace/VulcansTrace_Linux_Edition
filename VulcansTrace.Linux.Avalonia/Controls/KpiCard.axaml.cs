using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// A reusable dashboard KPI card with an icon, label, large value, optional trend text,
/// and an alert state that tints the background and draws a colored accent bar.
/// </summary>
public partial class KpiCard : UserControl
{
    /// <summary>
    /// Defines the <see cref="Icon"/> property.
    /// </summary>
    public static readonly StyledProperty<string> IconProperty =
        AvaloniaProperty.Register<KpiCard, string>(nameof(Icon));

    /// <summary>
    /// Defines the <see cref="Label"/> property.
    /// </summary>
    public static readonly StyledProperty<string> LabelProperty =
        AvaloniaProperty.Register<KpiCard, string>(nameof(Label));

    /// <summary>
    /// Defines the <see cref="Value"/> property.
    /// </summary>
    public static readonly StyledProperty<object?> ValueProperty =
        AvaloniaProperty.Register<KpiCard, object?>(nameof(Value));

    /// <summary>
    /// Defines the <see cref="AccentBrush"/> property.
    /// </summary>
    public static readonly StyledProperty<IBrush?> AccentBrushProperty =
        AvaloniaProperty.Register<KpiCard, IBrush?>(nameof(AccentBrush));

    /// <summary>
    /// Defines the <see cref="GlowBrush"/> property.
    /// </summary>
    public static readonly StyledProperty<IBrush?> GlowBrushProperty =
        AvaloniaProperty.Register<KpiCard, IBrush?>(nameof(GlowBrush));

    /// <summary>
    /// Defines the <see cref="TrendText"/> property.
    /// </summary>
    public static readonly StyledProperty<string> TrendTextProperty =
        AvaloniaProperty.Register<KpiCard, string>(nameof(TrendText));

    /// <summary>
    /// Defines the <see cref="IsAlert"/> property.
    /// </summary>
    public static readonly StyledProperty<bool> IsAlertProperty =
        AvaloniaProperty.Register<KpiCard, bool>(nameof(IsAlert));

    /// <summary>
    /// Gets or sets the Material Design icon glyph name (e.g., "mdi-chart-box").
    /// </summary>
    public string Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    /// <summary>
    /// Gets or sets the card label displayed next to the icon.
    /// </summary>
    public string Label
    {
        get => GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    /// <summary>
    /// Gets or sets the primary value displayed in large type.
    /// </summary>
    public object? Value
    {
        get => GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    /// <summary>
    /// Gets or sets the accent brush used for the icon, label emphasis, and alert bar.
    /// </summary>
    public IBrush? AccentBrush
    {
        get => GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    /// <summary>
    /// Gets or sets the brush used for the alert-state background tint.
    /// </summary>
    public IBrush? GlowBrush
    {
        get => GetValue(GlowBrushProperty);
        set => SetValue(GlowBrushProperty, value);
    }

    /// <summary>
    /// Gets or sets the small trend text shown below the value.
    /// </summary>
    public string TrendText
    {
        get => GetValue(TrendTextProperty);
        set => SetValue(TrendTextProperty, value);
    }

    /// <summary>
    /// Gets or sets a value indicating whether the card should render in alert state.
    /// </summary>
    public bool IsAlert
    {
        get => GetValue(IsAlertProperty);
        set => SetValue(IsAlertProperty, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KpiCard"/> class.
    /// </summary>
    public KpiCard()
    {
        InitializeComponent();
    }
}
