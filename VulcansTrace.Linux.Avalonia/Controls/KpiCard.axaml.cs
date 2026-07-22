using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.VisualTree;

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
    /// Defines the <see cref="Command"/> property (click-through; card is inert when unset).
    /// </summary>
    public static readonly StyledProperty<System.Windows.Input.ICommand?> CommandProperty =
        AvaloniaProperty.Register<KpiCard, System.Windows.Input.ICommand?>(nameof(Command));

    /// <summary>
    /// Defines the <see cref="CommandParameter"/> property.
    /// </summary>
    public static readonly StyledProperty<object?> CommandParameterProperty =
        AvaloniaProperty.Register<KpiCard, object?>(nameof(CommandParameter));

    /// <summary>
    /// Defines the <see cref="CardAutomationId"/> property for the click-through overlay.
    /// </summary>
    public static readonly StyledProperty<string> CardAutomationIdProperty =
        AvaloniaProperty.Register<KpiCard, string>(nameof(CardAutomationId));

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
    /// Gets or sets the command invoked when the card is clicked. When null the
    /// card is inert (no click-through overlay).
    /// </summary>
    public System.Windows.Input.ICommand? Command
    {
        get => GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }

    /// <summary>Gets or sets the parameter passed to <see cref="Command"/>.</summary>
    public object? CommandParameter
    {
        get => GetValue(CommandParameterProperty);
        set => SetValue(CommandParameterProperty, value);
    }

    /// <summary>Gets or sets the automation id of the click-through overlay button.</summary>
    public string CardAutomationId
    {
        get => GetValue(CardAutomationIdProperty);
        set => SetValue(CardAutomationIdProperty, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KpiCard"/> class.
    /// </summary>
    public KpiCard()
    {
        InitializeComponent();
    }

    /// <inheritdoc />
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ValueProperty)
        {
            if (_valueInitialized)
            {
                StartValueAnimation();
            }

            _valueInitialized = true;
        }
    }

    private bool _valueInitialized;
    private CancellationTokenSource? _valueAnimationCts;

    /// <inheritdoc />
    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        CancelValueAnimation();
        base.OnDetachedFromVisualTree(e);
    }

    private void StartValueAnimation()
    {
        var animationCts = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _valueAnimationCts, animationCts);
        previous?.Cancel();

        _ = AnimateValueChangeAsync(animationCts);
    }

    private void CancelValueAnimation()
    {
        var cts = Interlocked.Exchange(ref _valueAnimationCts, null);
        cts?.Cancel();
    }

    private async Task AnimateValueChangeAsync(CancellationTokenSource animationCts)
    {
        var valueText = this.FindControl<TextBlock>("ValueText");
        if (valueText is null)
        {
            CompleteValueAnimation(animationCts);
            return;
        }

        var animation = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(300),
            Children =
            {
                new KeyFrame
                {
                    Setters = { new Setter(Visual.OpacityProperty, 1.0) },
                    KeyTime = TimeSpan.Zero
                },
                new KeyFrame
                {
                    Setters = { new Setter(Visual.OpacityProperty, 0.5) },
                    KeyTime = TimeSpan.FromMilliseconds(100)
                },
                new KeyFrame
                {
                    Setters = { new Setter(Visual.OpacityProperty, 1.0) },
                    KeyTime = TimeSpan.FromMilliseconds(300)
                }
            }
        };

        try
        {
            await animation.RunAsync(valueText, animationCts.Token);
        }
        catch (OperationCanceledException) when (animationCts.IsCancellationRequested)
        {
            // Expected when a newer value change or visual-tree detach supersedes this animation.
        }
        catch (Exception) when (animationCts.IsCancellationRequested)
        {
            // Avalonia can surface teardown cancellation through animation cleanup paths.
        }
        catch (Exception)
        {
            // The KPI pulse is decorative; keep animation failures from escaping fire-and-forget.
        }
        finally
        {
            CompleteValueAnimation(animationCts);
        }
    }

    private void CompleteValueAnimation(CancellationTokenSource animationCts)
    {
        Interlocked.CompareExchange(ref _valueAnimationCts, null, animationCts);
        animationCts.Dispose();
    }
}
