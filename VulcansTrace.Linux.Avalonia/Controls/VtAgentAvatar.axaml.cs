using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// A reusable circular trace-glyph avatar used on Agent-owned surfaces.
/// </summary>
public partial class VtAgentAvatar : UserControl
{
    public static readonly StyledProperty<double> AvatarSizeProperty = AvaloniaProperty.Register<VtAgentAvatar, double>(
        nameof(AvatarSize), defaultValue: 28.0);

    public VtAgentAvatar()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Gets or sets the total width/height of the avatar.
    /// </summary>
    public double AvatarSize
    {
        get => GetValue(AvatarSizeProperty);
        set => SetValue(AvatarSizeProperty, value);
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
