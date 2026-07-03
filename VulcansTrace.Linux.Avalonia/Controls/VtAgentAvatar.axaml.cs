using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// A reusable circular "VT" avatar used in the header, chat bubbles, and typing indicator.
/// </summary>
public partial class VtAgentAvatar : UserControl
{
    public static readonly StyledProperty<double> AvatarSizeProperty = AvaloniaProperty.Register<VtAgentAvatar, double>(
        nameof(AvatarSize), defaultValue: 28.0);

    public static readonly StyledProperty<double> AvatarFontSizeProperty = AvaloniaProperty.Register<VtAgentAvatar, double>(
        nameof(AvatarFontSize), defaultValue: 10.0);

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

    /// <summary>
    /// Gets or sets the font size of the "VT" text.
    /// </summary>
    public double AvatarFontSize
    {
        get => GetValue(AvatarFontSizeProperty);
        set => SetValue(AvatarFontSizeProperty, value);
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
