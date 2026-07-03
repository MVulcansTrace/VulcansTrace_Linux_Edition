using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Span = Avalonia.Controls.Documents.Span;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a lightweight markdown string into a collection of Avalonia <see cref="Inline"/> elements.
/// Supports **bold**, *italic* (single asterisk only), `inline code`, bare URLs, markdown links, and paragraph breaks.
/// Underscore is intentionally not treated as italic to avoid mangling file_name and snake_case identifiers.
/// Bold and italic are parsed recursively so URLs, code spans, and links can appear inside them.
/// </summary>
public sealed class MarkdownInlinesConverter : IValueConverter
{
    // Inline code: `code` (non-greedy). Backticks inside are not supported.
    private static readonly Regex InlineCodePattern = new(@"`(.+?)`", RegexOptions.Compiled);

    // Bare URLs: http:// or https:// until whitespace or common punctuation.
    // Query strings (?...), ports (:...), and dots (.) are allowed inside the URL; a trailing
    // sentence-period is stripped in post-processing.
    private static readonly Regex UrlPattern = new(
        @"https?://[^\s\]\)\}>,;!'""*]+",
        RegexOptions.Compiled);

    // Markdown link: [text](url)
    private static readonly Regex LinkPattern = new(
        @"\[([^\]]+)\]\((https?://[^\)]+)\)",
        RegexOptions.Compiled);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string text || string.IsNullOrWhiteSpace(text))
            return Array.Empty<Inline>();

        return Convert(text, createOpenUrlCommand: null);
    }

    /// <summary>
    /// Converts markdown text into inline elements, optionally rendering URLs as clickable buttons.
    /// </summary>
    /// <param name="text">The markdown text to convert.</param>
    /// <param name="createOpenUrlCommand">Optional factory that creates a command to open a URL.</param>
    /// <returns>A sequence of inline elements.</returns>
    public IEnumerable<Inline> Convert(string text, Func<string, ICommand>? createOpenUrlCommand)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<Inline>();

        var inlines = new List<Inline>();
        var paragraphs = text.Split(new[] { "\n\n" }, StringSplitOptions.None);

        for (var p = 0; p < paragraphs.Length; p++)
        {
            ParseParagraph(paragraphs[p], inlines, createOpenUrlCommand);

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

    private static void ParseParagraph(string paragraph, List<Inline> inlines, Func<string, ICommand>? createOpenUrlCommand)
    {
        var lines = paragraph.Split('\n');

        for (var l = 0; l < lines.Length; l++)
        {
            ParseInline(lines[l], inlines, createOpenUrlCommand);

            if (l < lines.Length - 1)
                inlines.Add(new LineBreak());
        }
    }

    private static void ParseInline(string line, List<Inline> inlines, Func<string, ICommand>? createOpenUrlCommand)
    {
        // Replace code spans, markdown links, and bare URLs with sentinel characters.
        // Bold and italic are *not* replaced here; they are parsed recursively so that
        // placeholders can be expanded inside them.
        var placeholders = new List<Placeholder>();
        var normalized = SubstituteNonNestedTokens(line, placeholders);

        AppendParsed(normalized, placeholders, inlines, createOpenUrlCommand);
    }

    private static string SubstituteNonNestedTokens(string line, List<Placeholder> placeholders)
    {
        var normalized = line;

        normalized = InlineCodePattern.Replace(normalized, match =>
            RegisterPlaceholder(placeholders, match, PlaceholderKind.InlineCode, match.Groups[1].Value));

        normalized = LinkPattern.Replace(normalized, match =>
            RegisterPlaceholder(placeholders, match, PlaceholderKind.Link,
                match.Groups[1].Value, NormalizeUrl(match.Groups[2].Value)));

        normalized = UrlPattern.Replace(normalized, match =>
            RegisterPlaceholder(placeholders, match, PlaceholderKind.Url, NormalizeUrl(match.Value)));

        return normalized;
    }

    private static void AppendParsed(string text, List<Placeholder> placeholders, IList<Inline> inlines, Func<string, ICommand>? createOpenUrlCommand)
    {
        if (string.IsNullOrEmpty(text))
            return;

        var buffer = new StringBuilder();
        var i = 0;
        while (i < text.Length)
        {
            var placeholder = placeholders.FirstOrDefault(p => p.StartChar == text[i]);
            if (placeholder != null)
            {
                FlushBuffer(buffer, inlines);
                AppendPlaceholder(placeholder, inlines, createOpenUrlCommand);
                i++;
                continue;
            }

            // Bold: **text**
            if (i < text.Length - 1 && text[i] == '*' && text[i + 1] == '*')
            {
                var close = FindClosingBold(text, i + 2);
                if (close >= 0)
                {
                    FlushBuffer(buffer, inlines);
                    var bold = new Bold();
                    AppendParsed(text.Substring(i + 2, close - (i + 2)), placeholders, bold.Inlines, createOpenUrlCommand);
                    inlines.Add(bold);
                    i = close + 2;
                    continue;
                }
            }

            // Italic: *text* (bounded by whitespace/punctuation)
            if (text[i] == '*' && IsItalicOpenBoundary(text, i))
            {
                var close = FindClosingItalic(text, i + 1);
                if (close >= 0)
                {
                    FlushBuffer(buffer, inlines);
                    var italic = new Italic();
                    AppendParsed(text.Substring(i + 1, close - (i + 1)), placeholders, italic.Inlines, createOpenUrlCommand);
                    inlines.Add(italic);
                    i = close + 1;
                    continue;
                }
            }

            buffer.Append(text[i]);
            i++;
        }

        FlushBuffer(buffer, inlines);
    }

    private static int FindClosingBold(string text, int start)
    {
        // Bold does not nest in this lightweight parser; the first ** after the content start
        // is treated as the closing marker.
        var i = start;
        while (i < text.Length - 1)
        {
            if (text[i] == '*' && text[i + 1] == '*')
                return i;
            i++;
        }
        return -1;
    }

    private static int FindClosingItalic(string text, int start)
    {
        var i = start;
        while (i < text.Length)
        {
            if (i < text.Length - 1 && text[i] == '*' && text[i + 1] == '*')
            {
                // Skip nested bold blocks entirely so their * markers are not mistaken for
                // italic closings.
                var boldClose = FindClosingBold(text, i + 2);
                if (boldClose < 0)
                    return -1;
                i = boldClose + 2;
                continue;
            }

            if (text[i] == '*' && IsItalicCloseBoundary(text, i))
                return i;

            i++;
        }
        return -1;
    }

    private static bool IsItalicOpenBoundary(string text, int index)
    {
        // Must be at the start of the string or preceded by whitespace.
        if (index > 0 && !char.IsWhiteSpace(text[index - 1]))
            return false;

        // A leading ** is bold, not italic.
        if (index < text.Length - 1 && text[index + 1] == '*')
            return false;

        return true;
    }

    private static bool IsItalicCloseBoundary(string text, int index)
    {
        // Must be followed by whitespace, end of string, or one of the sentence punctuation chars.
        if (index < text.Length - 1)
        {
            var next = text[index + 1];
            if (!char.IsWhiteSpace(next) && ". ,;:!?".IndexOf(next) < 0)
                return false;
        }

        // A trailing ** is bold, not italic.
        if (index > 0 && text[index - 1] == '*')
            return false;

        return true;
    }

    private static void FlushBuffer(StringBuilder buffer, IList<Inline> inlines)
    {
        if (buffer.Length == 0)
            return;

        inlines.Add(new Run(buffer.ToString()));
        buffer.Clear();
    }

    private static string RegisterPlaceholder(
        List<Placeholder> placeholders,
        Match match,
        PlaceholderKind kind,
        string content,
        string? url = null)
    {
        var startChar = (char)('\xE000' + placeholders.Count);
        placeholders.Add(new Placeholder(startChar, kind, content, url));
        return startChar.ToString();
    }

    private static void AppendPlaceholder(Placeholder placeholder, IList<Inline> inlines, Func<string, ICommand>? createOpenUrlCommand)
    {
        Inline inline = placeholder.Kind switch
        {
            PlaceholderKind.InlineCode => CreateInlineCode(placeholder.Content),
            PlaceholderKind.Url => createOpenUrlCommand is null
                ? CreateUrlSpan(placeholder.Content, placeholder.Content)
                : CreateUrlButton(placeholder.Content, placeholder.Content, createOpenUrlCommand(placeholder.Content)),
            PlaceholderKind.Link => createOpenUrlCommand is null
                ? CreateUrlSpan(placeholder.Content, placeholder.Url!)
                : CreateUrlButton(placeholder.Content, placeholder.Url!, createOpenUrlCommand(placeholder.Url!)),
            _ => new Run(placeholder.Content)
        };

        inlines.Add(inline);
    }

    /// <summary>
    /// Strips a single trailing period when it is clearly sentence punctuation rather than part
    /// of the URL. We only strip when the URL still contains a domain dot after trimming, which
    /// prevents turning "https://com." into "https://com".
    /// </summary>
    private static string NormalizeUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
            return url;

        if (url.EndsWith('.') && url.Length > 1)
        {
            var withoutTrailingDot = url.Substring(0, url.Length - 1);
            if (withoutTrailingDot.Contains('.'))
                return withoutTrailingDot;
        }

        return url;
    }

    private static Inline CreateInlineCode(string code)
    {
        var app = Application.Current;
        var textBlock = new TextBlock
        {
            Text = code,
            FontFamily = app?.TryFindResource("VtFontFamilyMono", null, out var mono) == true ? (FontFamily)mono! : new FontFamily("Consolas,Monospace"),
            FontSize = app?.TryFindResource("VtFontSizeXs", null, out var size) == true ? (double)size! : 15.0,
            Foreground = app?.TryFindResource("VtInlineCodeForegroundBrush", null, out var fg) == true ? (IBrush)fg! : new SolidColorBrush(Colors.LightGray),
            VerticalAlignment = global::Avalonia.Layout.VerticalAlignment.Center
        };

        var border = new Border
        {
            Background = app?.TryFindResource("VtInlineCodeBackgroundBrush", null, out var bg) == true ? (IBrush)bg! : new SolidColorBrush(Colors.DarkSlateGray),
            BorderBrush = app?.TryFindResource("VtCodeBorderBrush", null, out var borderBrush) == true ? (IBrush)borderBrush! : new SolidColorBrush(Colors.Gray),
            BorderThickness = new Thickness(1),
            CornerRadius = app?.TryFindResource("VtRadiusSm", null, out var radius) == true ? (CornerRadius)radius! : new CornerRadius(4),
            Padding = new Thickness(4, 2),
            Child = textBlock
        };

        return new InlineUIContainer { Child = border };
    }

    private static Inline CreateUrlSpan(string text, string url)
    {
        var app = Application.Current;
        var span = new Span();
        span.Inlines.Add(new Run(text));
        span.Foreground = app?.TryFindResource("VtPrimaryBrush", null, out var fg) == true ? (IBrush)fg! : new SolidColorBrush(Colors.CornflowerBlue);
        span.TextDecorations = TextDecorations.Underline;
        return span;
    }

    private static Inline CreateUrlButton(string text, string url, ICommand openUrlCommand)
    {
        var app = Application.Current;
        var foreground = app?.TryFindResource("VtPrimaryBrush", null, out var fg) == true ? (IBrush)fg! : new SolidColorBrush(Colors.CornflowerBlue);

        var button = new Button
        {
            Content = new TextBlock
            {
                Text = text,
                TextDecorations = TextDecorations.Underline,
                Foreground = foreground
            },
            Command = openUrlCommand,
            CommandParameter = url,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(0),
            Margin = new Thickness(0)
        };
        return new InlineUIContainer { Child = button };
    }

    private enum PlaceholderKind
    {
        InlineCode,
        Url,
        Link
    }

    private sealed class Placeholder
    {
        public Placeholder(char startChar, PlaceholderKind kind, string content, string? url = null)
        {
            StartChar = startChar;
            Kind = kind;
            Content = content;
            Url = url;
        }

        public char StartChar { get; }
        public PlaceholderKind Kind { get; }
        public string Content { get; }
        public string? Url { get; }
    }
}
