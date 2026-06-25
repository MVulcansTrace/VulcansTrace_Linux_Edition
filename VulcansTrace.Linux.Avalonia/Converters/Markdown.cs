using System.Collections.Generic;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Renders a lightweight-markdown string (e.g. <c>**bold**</c>, <c>*italic*</c>) as styled
/// <see cref="Inline"/> elements on a <see cref="TextBlock"/>. <see cref="TextBlock.Inlines"/>
/// has no setter, so a plain <c>{Binding}</c> can't populate it; bind this attached property
/// instead and it runs <see cref="MarkdownInlinesConverter"/> to rebuild the Inlines whenever
/// the bound text changes.
/// </summary>
public sealed class Markdown
{
    public static readonly AttachedProperty<string?> TextProperty =
        AvaloniaProperty.RegisterAttached<Markdown, TextBlock, string?>("Text");

    private static readonly MarkdownInlinesConverter Converter = new();

    static Markdown()
    {
        TextProperty.Changed.AddClassHandler<TextBlock>(OnTextChanged);
    }

    public static void SetText(TextBlock element, string? value) => element.SetValue(TextProperty, value);

    public static string? GetText(TextBlock element) => (string?)element.GetValue(TextProperty);

    private static void OnTextChanged(TextBlock textBlock, AvaloniaPropertyChangedEventArgs e)
    {
        var inlines = (IEnumerable<Inline>)Converter.Convert(
            (string?)e.NewValue, typeof(object), null, CultureInfo.InvariantCulture);

        // Inlines is a nullable StyledProperty, lazily populated; create the collection on first use.
        textBlock.Inlines ??= new InlineCollection();
        var collection = textBlock.Inlines;
        collection.Clear();
        foreach (var inline in inlines)
        {
            collection.Add(inline);
        }
    }
}
