using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// A reusable empty-state view with an icon, headline, description, and optional action button.
/// </summary>
public partial class EmptyStateView : UserControl
{
    /// <summary>
    /// Defines the <see cref="Icon"/> property.
    /// </summary>
    public static readonly StyledProperty<string> IconProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(Icon));

    /// <summary>
    /// Defines the <see cref="Headline"/> property.
    /// </summary>
    public static readonly StyledProperty<string> HeadlineProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(Headline));

    /// <summary>
    /// Defines the <see cref="Description"/> property.
    /// </summary>
    public static readonly StyledProperty<string> DescriptionProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(Description));

    /// <summary>
    /// Defines the <see cref="ActionText"/> property.
    /// </summary>
    public static readonly StyledProperty<string> ActionTextProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(ActionText));

    /// <summary>
    /// Defines the <see cref="ActionIcon"/> property.
    /// </summary>
    public static readonly StyledProperty<string> ActionIconProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(ActionIcon));

    /// <summary>
    /// Defines the <see cref="ActionCommand"/> property.
    /// </summary>
    public static readonly StyledProperty<ICommand?> ActionCommandProperty =
        AvaloniaProperty.Register<EmptyStateView, ICommand?>(nameof(ActionCommand));

    /// <summary>
    /// Defines the <see cref="ActionAutomationId"/> property.
    /// </summary>
    public static readonly StyledProperty<string> ActionAutomationIdProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(ActionAutomationId));

    /// <summary>
    /// Defines the <see cref="ActionAutomationName"/> property.
    /// </summary>
    public static readonly StyledProperty<string> ActionAutomationNameProperty =
        AvaloniaProperty.Register<EmptyStateView, string>(nameof(ActionAutomationName));

    /// <summary>
    /// Gets or sets the Material Design icon glyph name shown above the headline.
    /// </summary>
    public string Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    /// <summary>
    /// Gets or sets the empty-state headline.
    /// </summary>
    public string Headline
    {
        get => GetValue(HeadlineProperty);
        set => SetValue(HeadlineProperty, value);
    }

    /// <summary>
    /// Gets or sets the descriptive body text.
    /// </summary>
    public string Description
    {
        get => GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    /// <summary>
    /// Gets or sets the text of the action button.
    /// </summary>
    public string ActionText
    {
        get => GetValue(ActionTextProperty);
        set => SetValue(ActionTextProperty, value);
    }

    /// <summary>
    /// Gets or sets the optional icon shown inside the action button.
    /// </summary>
    public string ActionIcon
    {
        get => GetValue(ActionIconProperty);
        set => SetValue(ActionIconProperty, value);
    }

    /// <summary>
    /// Gets or sets the command invoked by the action button.
    /// </summary>
    public ICommand? ActionCommand
    {
        get => GetValue(ActionCommandProperty);
        set => SetValue(ActionCommandProperty, value);
    }

    /// <summary>
    /// Gets or sets the automation ID applied to the action button.
    /// </summary>
    public string ActionAutomationId
    {
        get => GetValue(ActionAutomationIdProperty);
        set => SetValue(ActionAutomationIdProperty, value);
    }

    /// <summary>
    /// Gets or sets the stable accessible name applied to the action button.
    /// </summary>
    public string ActionAutomationName
    {
        get => GetValue(ActionAutomationNameProperty);
        set => SetValue(ActionAutomationNameProperty, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EmptyStateView"/> class.
    /// </summary>
    public EmptyStateView()
    {
        InitializeComponent();
    }
}
