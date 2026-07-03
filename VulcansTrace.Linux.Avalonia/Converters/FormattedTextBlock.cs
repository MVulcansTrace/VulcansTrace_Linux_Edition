using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Attached property that populates a <see cref="TextBlock.Inlines"/> collection from a
/// sequence of pre-built <see cref="Inline"/> objects. This is needed because
/// <see cref="InlineCollection"/> has no public setter and cannot be bound directly.
/// </summary>
public sealed class FormattedTextBlock
{
    public static readonly AttachedProperty<IEnumerable?> InlinesSourceProperty =
        AvaloniaProperty.RegisterAttached<FormattedTextBlock, TextBlock, IEnumerable?>("InlinesSource");

    static FormattedTextBlock()
    {
        InlinesSourceProperty.Changed.AddClassHandler<TextBlock>(OnInlinesSourceChanged);
    }

    public static void SetInlinesSource(TextBlock element, IEnumerable? value) => element.SetValue(InlinesSourceProperty, value);

    public static IEnumerable? GetInlinesSource(TextBlock element) => (IEnumerable?)element.GetValue(InlinesSourceProperty);

    private static void OnInlinesSourceChanged(TextBlock textBlock, AvaloniaPropertyChangedEventArgs e)
    {
        textBlock.Inlines ??= new InlineCollection();
        var collection = textBlock.Inlines;
        collection.Clear();

        if (e.NewValue is not IEnumerable source)
            return;

        foreach (var item in source)
        {
            if (item is Inline inline)
                collection.Add(inline);
        }
    }
}
