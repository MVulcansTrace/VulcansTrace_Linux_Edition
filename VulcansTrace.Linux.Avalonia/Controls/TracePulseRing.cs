using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using VulcansTrace.Linux.Avalonia.Services;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Renders the Agent's truthful progress/status ring without replacing its
/// accessible avatar content.
/// </summary>
public sealed class TracePulseRing : Control
{
    public static readonly StyledProperty<double> ProgressProperty =
        AvaloniaProperty.Register<TracePulseRing, double>(nameof(Progress));

    public static readonly StyledProperty<bool> IsActiveProperty =
        AvaloniaProperty.Register<TracePulseRing, bool>(nameof(IsActive));

    public static readonly StyledProperty<bool> IsIndeterminateProperty =
        AvaloniaProperty.Register<TracePulseRing, bool>(nameof(IsIndeterminate));

    public static readonly StyledProperty<IBrush?> AccentBrushProperty =
        AvaloniaProperty.Register<TracePulseRing, IBrush?>(nameof(AccentBrush));

    public static readonly StyledProperty<IBrush?> TrackBrushProperty =
        AvaloniaProperty.Register<TracePulseRing, IBrush?>(nameof(TrackBrush));

    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<TracePulseRing, double>(nameof(StrokeThickness), 2.0);

    private readonly DispatcherTimer _rotationTimer;
    private double _startAngle = -90;
    private bool _isAttached;

    static TracePulseRing()
    {
        AffectsRender<TracePulseRing>(
            ProgressProperty,
            IsActiveProperty,
            IsIndeterminateProperty,
            AccentBrushProperty,
            TrackBrushProperty,
            StrokeThicknessProperty);
    }

    public TracePulseRing()
    {
        IsHitTestVisible = false;
        _rotationTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(32) };
        _rotationTimer.Tick += (_, _) =>
        {
            _startAngle = (_startAngle + 5) % 360;
            InvalidateVisual();
        };
    }

    /// <summary>Gets or sets determinate progress from 0 through 100.</summary>
    public double Progress
    {
        get => GetValue(ProgressProperty);
        set => SetValue(ProgressProperty, value);
    }

    /// <summary>Gets or sets whether an operation is currently running.</summary>
    public bool IsActive
    {
        get => GetValue(IsActiveProperty);
        set => SetValue(IsActiveProperty, value);
    }

    /// <summary>Gets or sets whether the active operation lacks a percentage.</summary>
    public bool IsIndeterminate
    {
        get => GetValue(IsIndeterminateProperty);
        set => SetValue(IsIndeterminateProperty, value);
    }

    /// <summary>Gets or sets the semantic state color.</summary>
    public IBrush? AccentBrush
    {
        get => GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    /// <summary>Gets or sets the quiet background ring color.</summary>
    public IBrush? TrackBrush
    {
        get => GetValue(TrackBrushProperty);
        set => SetValue(TrackBrushProperty, value);
    }

    /// <summary>Gets or sets the ring thickness.</summary>
    public double StrokeThickness
    {
        get => GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    /// <inheritdoc />
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == IsActiveProperty || change.Property == IsIndeterminateProperty)
            UpdateRotationTimer();
    }

    /// <inheritdoc />
    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _isAttached = true;
        UpdateRotationTimer();
    }

    /// <inheritdoc />
    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _isAttached = false;
        _rotationTimer.Stop();
        base.OnDetachedFromVisualTree(e);
    }

    /// <inheritdoc />
    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var thickness = Math.Max(1, StrokeThickness);
        var radius = Math.Max(0, Math.Min(Bounds.Width, Bounds.Height) / 2 - thickness / 2);
        if (radius <= 0)
            return;

        var center = new Point(Bounds.Width / 2, Bounds.Height / 2);
        if (TrackBrush is not null)
            context.DrawEllipse(null, new Pen(TrackBrush, thickness), center, radius, radius);

        if (AccentBrush is null)
            return;

        var normalized = Math.Clamp(Progress, 0, 100);
        var sweep = IsActive && IsIndeterminate ? 92 : normalized * 3.6;
        if (IsActive && sweep < 10)
            sweep = 10;
        if (sweep <= 0)
            return;

        var pen = new Pen(AccentBrush, thickness, null, PenLineCap.Round, PenLineJoin.Round);
        if (sweep >= 359.5)
        {
            context.DrawEllipse(null, pen, center, radius, radius);
            return;
        }

        var startAngle = IsActive && IsIndeterminate ? _startAngle : -90;
        var start = PointOnCircle(center, radius, startAngle);
        var end = PointOnCircle(center, radius, startAngle + sweep);
        var geometry = new StreamGeometry();
        using (var geometryContext = geometry.Open())
        {
            geometryContext.BeginFigure(start, false);
            geometryContext.ArcTo(
                end,
                new Size(radius, radius),
                0,
                sweep > 180,
                SweepDirection.Clockwise,
                true);
        }
        context.DrawGeometry(null, pen, geometry);
    }

    private static Point PointOnCircle(Point center, double radius, double degrees)
    {
        var radians = degrees * Math.PI / 180;
        return new Point(
            center.X + radius * Math.Cos(radians),
            center.Y + radius * Math.Sin(radians));
    }

    private void UpdateRotationTimer()
    {
        if (_isAttached && IsActive && IsIndeterminate && MotionSettings.IsEnabled)
            _rotationTimer.Start();
        else
            _rotationTimer.Stop();
    }
}
