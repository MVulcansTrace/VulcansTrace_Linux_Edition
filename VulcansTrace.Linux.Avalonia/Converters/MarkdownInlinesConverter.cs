using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Avalonia.Controls.Documents;
using Avalonia.Data.Converters;
using Span = Avalonia.Controls.Documents.Span;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a lightweight markdown string into a collection of Avalonia <see cref="Inline"/> elements.
/// Supports **bold** and *italic* (single asterisk only), plus paragraph and line breaks.
/// Underscore is intentionally not treated as italic to avoid mangling file_name and snake_case identifiers.
/// </summary>
public sealed class MarkdownInlinesConverter : IValueConverter
{
    // Bold: **text** (non-greedy).
    private static readonly Regex BoldPattern = new(@"\*\*(.+?)\*\*", RegexOptions.Compiled);

    // Italic: *text* only when bounded by whitespace or punctuation, never inside words.
    private static readonly Regex ItalicPattern = new(@"(?<=(^|\s))\*(.+?)\*(?=(\s|$|[.,;:!?]))", RegexOptions.Compiled);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string text || string.IsNullOrWhiteSpace(text))
            return Array.Empty<Inline>();

        var inlines = new List<Inline>();
        var paragraphs = text.Split(new[] { "\n\n" }, StringSplitOptions.None);

        for (var p = 0; p < paragraphs.Length; p++)
        {
            ParseParagraph(paragraphs[p], inlines);

            if (p < paragraphs.Length - 1)
            {
                inlines.Add(new LineBreak());
                inlines.Add(new LineBreak());
            }
        }

        return inlines;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }

    private static void ParseParagraph(string paragraph, List<Inline> inlines)
    {
        var lines = paragraph.Split('\n');

        for (var l = 0; l < lines.Length; l++)
        {
            ParseInline(lines[l], inlines);

            if (l < lines.Length - 1)
                inlines.Add(new LineBreak());
        }
    }

    private static void ParseInline(string line, List<Inline> inlines)
    {
        // Replace **text** with a sentinel so we can process bold and italic in one pass.
        var normalized = BoldPattern.Replace(line, match => $"\x02{match.Groups[1].Value}\x02");
        normalized = ItalicPattern.Replace(normalized, match => $"\x1f{match.Groups[2].Value}\x1f");

        var buffer = new StringBuilder();
        var isBold = false;
        var isItalic = false;

        foreach (var ch in normalized)
        {
            if (ch == '\x02')
            {
                FlushBuffer(buffer, inlines, ref isBold, ref isItalic);
                isBold = !isBold;
                continue;
            }

            if (ch == '\x1f')
            {
                FlushBuffer(buffer, inlines, ref isBold, ref isItalic);
                isItalic = !isItalic;
                continue;
            }

            buffer.Append(ch);
        }

        FlushBuffer(buffer, inlines, ref isBold, ref isItalic);
    }

    private static void FlushBuffer(StringBuilder buffer, List<Inline> inlines, ref bool isBold, ref bool isItalic)
    {
        if (buffer.Length == 0)
            return;

        var text = buffer.ToString();
        buffer.Clear();

        var run = new Run(text);

        if (isBold && isItalic)
        {
            var italic = new Italic();
            italic.Inlines.Add(run);
            var bold = new Bold();
            bold.Inlines.Add(italic);
            inlines.Add(bold);
        }
        else if (isBold)
        {
            var bold = new Bold();
            bold.Inlines.Add(run);
            inlines.Add(bold);
        }
        else if (isItalic)
        {
            var italic = new Italic();
            italic.Inlines.Add(run);
            inlines.Add(italic);
        }
        else
        {
            inlines.Add(run);
        }
    }
}
