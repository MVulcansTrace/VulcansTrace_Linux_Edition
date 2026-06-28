using Avalonia;
using Avalonia.Controls;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// A lightweight empty-state card for "your filter/search returned no matches" scenarios.
/// Unlike <see cref="EmptyStateView"/>, this variant has no action button and is meant
/// to sit inside a view that already has data loaded.
/// </summary>
public partial class FilterEmptyStateView : UserControl
{
    /// <summary>
    /// Defines the <see cref="Icon"/> property.
    /// </summary>
    public static readonly StyledProperty<string> IconProperty =
        AvaloniaProperty.Register<FilterEmptyStateView, string>(nameof(Icon));

    /// <summary>
    /// Defines the <see cref="Headline"/> property.
    /// </summary>
    public static readonly StyledProperty<string> HeadlineProperty =
        AvaloniaProperty.Register<FilterEmptyStateView, string>(nameof(Headline));

    /// <summary>
    /// Defines the <see cref="Description"/> property.
    /// </summary>
    public static readonly StyledProperty<string> DescriptionProperty =
        AvaloniaProperty.Register<FilterEmptyStateView, string>(nameof(Description));

    /// <summary>
    /// Gets or sets the Material Design icon glyph name (e.g., "mdi-filter-remove-outline").
    /// </summary>
    public string Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    /// <summary>
    /// Gets or sets the headline text displayed below the icon.
    /// </summary>
    public string Headline
    {
        get => GetValue(HeadlineProperty);
        set => SetValue(HeadlineProperty, value);
    }

    /// <summary>
    /// Gets or sets the descriptive text displayed below the headline.
    /// </summary>
    public string Description
    {
        get => GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FilterEmptyStateView"/> class.
    /// </summary>
    public FilterEmptyStateView()
    {
        InitializeComponent();
    }
}
