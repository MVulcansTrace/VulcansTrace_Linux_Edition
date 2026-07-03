using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Input;
using Avalonia.Controls.Documents;
using Avalonia.Data.Converters;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Converters;

/// <summary>
/// Converts a lightweight markdown string into a sequence of <see cref="AgentMessageBlock"/>
/// view-model objects. Supports paragraphs, inline formatting, bullet/numbered lists,
/// and fenced code blocks with an optional language label.
/// </summary>
public sealed class MarkdownBlocksConverter : IValueConverter
{
    // Fenced code block: ```[language]\ncode\n```
    private static readonly Regex FencedCodePattern = new(
        @"^```\s*(\S*)\s*\n(.*?)\n```\s*$",
        RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.Multiline);

    // Bullet list item: - item or * item at the start of a line.
    private static readonly Regex BulletPattern = new(@"^(\s*)[-*]\s+(.*)$", RegexOptions.Compiled);

    // Numbered list item: 1. item at the start of a line.
    private static readonly Regex NumberedPattern = new(@"^(\s*)(\d+)\.\s+(.*)$", RegexOptions.Compiled);

    private readonly MarkdownInlinesConverter _inlineConverter = new();

    /// <summary>
    /// Parses the supplied markdown text into blocks.
    /// </summary>
    /// <param name="text">The markdown text to parse.</param>
    /// <param name="createCopyCommand">Factory that creates a copy command for a code block.</param>
    /// <param name="createOpenUrlCommand">Optional factory that creates an open-URL command for clickable links.</param>
    /// <returns>A list of message blocks.</returns>
    public IReadOnlyList<AgentMessageBlock> Parse(string text, Func<string, ICommand> createCopyCommand, Func<string, ICommand>? createOpenUrlCommand = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<AgentMessageBlock>();

        var blocks = new List<AgentMessageBlock>();
        var offset = 0;

        while (offset < text.Length)
        {
            var match = FencedCodePattern.Match(text, offset);
            if (match.Success && match.Index == offset)
            {
                var language = match.Groups[1].Value.Trim();
                var code = match.Groups[2].Value;
                blocks.Add(new CodeBlock(language, code, createCopyCommand(code)));
                offset = match.Index + match.Length;
                continue;
            }

            // Find the next fenced block or end of string.
            var nextFenceIndex = int.MaxValue;
            var nextFence = FencedCodePattern.Match(text, offset);
            if (nextFence.Success)
                nextFenceIndex = nextFence.Index;

            var prose = nextFenceIndex == int.MaxValue
                ? text.Substring(offset)
                : text.Substring(offset, nextFenceIndex - offset);

            blocks.AddRange(ParseProse(prose, createOpenUrlCommand));
            offset = nextFenceIndex == int.MaxValue ? text.Length : nextFenceIndex;
        }

        return blocks;
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException("Use Parse with a copy-command factory.");
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }

    private IEnumerable<AgentMessageBlock> ParseProse(string prose, Func<string, ICommand>? createOpenUrlCommand)
    {
        var paragraphs = prose.Split(new[] { "\n\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var paragraph in paragraphs)
        {
            var formatted = FormatListLines(paragraph);
            var inlines = createOpenUrlCommand is null
                ? (IEnumerable<Inline>)_inlineConverter.Convert(formatted, typeof(object), null, CultureInfo.InvariantCulture)
                : _inlineConverter.Convert(formatted, createOpenUrlCommand);
            yield return new ParagraphBlock(inlines.Cast<object>().ToList());
        }
    }

    private static string FormatListLines(string paragraph)
    {
        var lines = paragraph.Split('\n');
        var numberedCounter = 0;
        var inNumberedRun = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var bullet = BulletPattern.Match(line);
            if (bullet.Success)
            {
                lines[i] = $"{bullet.Groups[1].Value}• {bullet.Groups[2].Value}";
                inNumberedRun = false;
                continue;
            }

            var numbered = NumberedPattern.Match(line);
            if (numbered.Success)
            {
                if (!inNumberedRun)
                    numberedCounter = 1;

                lines[i] = $"{numbered.Groups[1].Value}{numberedCounter}.  {numbered.Groups[3].Value}";
                numberedCounter++;
                inNumberedRun = true;
            }
            else
            {
                inNumberedRun = false;
            }
        }

        return string.Join('\n', lines);
    }
}
