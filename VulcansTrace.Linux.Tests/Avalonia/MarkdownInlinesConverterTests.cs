using System.Globalization;
using System.Linq;
using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using VulcansTrace.Linux.Avalonia.Converters;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class MarkdownInlinesConverterTests
{
    private readonly MarkdownInlinesConverter _converter = new();

    [AvaloniaFact]
    public void Convert_PlainText_ReturnsSingleRun()
    {
        var inlines = Convert("Hello world");

        var run = Assert.Single(inlines.OfType<Run>());
        Assert.Equal("Hello world", run.Text);
    }

    [AvaloniaFact]
    public void Convert_BoldText_ReturnsBoldRun()
    {
        var inlines = Convert("**Hello**");

        var bold = Assert.Single(inlines.OfType<Bold>());
        var run = Assert.Single(bold.Inlines.OfType<Run>());
        Assert.Equal("Hello", run.Text);
    }



    [AvaloniaFact]
    public void Convert_MixedContent_ReturnsRunsAndBold()
    {
        var inlines = Convert("Hello **bold** world").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("Hello ", Assert.IsType<Run>(inlines[0]).Text);
        Assert.Equal("bold", Assert.IsType<Bold>(inlines[1]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" world", Assert.IsType<Run>(inlines[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_ParagraphBreak_ReturnsTwoLineBreaks()
    {
        var inlines = Convert("Line one\n\nLine two").ToList();

        var lineBreaks = inlines.OfType<LineBreak>().Count();
        Assert.Equal(2, lineBreaks);
    }

    [AvaloniaFact]
    public void Convert_EmptyString_ReturnsEmpty()
    {
        var inlines = Convert("");

        Assert.Empty(inlines);
    }

    [AvaloniaFact]
    public void Convert_Null_ReturnsEmpty()
    {
        var result = _converter.Convert(null, typeof(object), null, CultureInfo.InvariantCulture);

        Assert.Empty((System.Collections.IEnumerable)result);
    }

    [AvaloniaFact]
    public void Convert_ItalicText_ReturnsItalicRun()
    {
        var inlines = Convert("*Hello*");

        var italic = Assert.Single(inlines.OfType<Italic>());
        var run = Assert.Single(italic.Inlines.OfType<Run>());
        Assert.Equal("Hello", run.Text);
    }

    [AvaloniaFact]
    public void Convert_SnakeCase_PreservedAsPlainText()
    {
        var inlines = Convert("file_name_here and /path/to_some/file").ToList();

        Assert.All(inlines, inline => Assert.IsType<Run>(inline));
        var text = string.Join("", inlines.OfType<Run>().Select(r => r.Text));
        Assert.Equal("file_name_here and /path/to_some/file", text);
    }

    [AvaloniaFact]
    public void Convert_Underscore_NoLongerTreatedAsItalic()
    {
        var inlines = Convert("_Hello_").ToList();

        Assert.Single(inlines);
        Assert.Equal("_Hello_", Assert.IsType<Run>(inlines[0]).Text);
    }

    [AvaloniaFact]
    public void Convert_InlineCode_ReturnsInlineUIContainer()
    {
        var inlines = Convert("Use `sudo ufw status` to check.").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("Use ", Assert.IsType<Run>(inlines[0]).Text);
        Assert.IsType<InlineUIContainer>(inlines[1]);
        Assert.Equal(" to check.", Assert.IsType<Run>(inlines[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_BareUrl_ReturnsSpanWithUnderline()
    {
        var inlines = Convert("See https://example.com for details.").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("See ", Assert.IsType<Run>(inlines[0]).Text);
        var span = Assert.IsType<Span>(inlines[1]);
        Assert.NotNull(span.TextDecorations);
        Assert.Equal(" for details.", Assert.IsType<Run>(inlines[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_MarkdownLink_ReturnsSpanWithText()
    {
        var inlines = Convert("[docs](https://example.com)").ToList();

        var span = Assert.Single(inlines.OfType<Span>());
        var run = Assert.Single(span.Inlines.OfType<Run>());
        Assert.Equal("docs", run.Text);
    }

    [AvaloniaFact]
    public void Convert_UrlWithAdjacentBold_AsterisksDoNotLeakIntoLink()
    {
        var inlines = Convert("See https://x.com**now** for details.").ToList();

        Assert.Equal(4, inlines.Count);
        Assert.Equal("See ", Assert.IsType<Run>(inlines[0]).Text);
        var span = Assert.IsType<Span>(inlines[1]);
        Assert.Equal("https://x.com", span.Inlines.OfType<Run>().First().Text);
        var bold = Assert.IsType<Bold>(inlines[2]);
        Assert.Equal("now", bold.Inlines.OfType<Run>().First().Text);
        Assert.Equal(" for details.", Assert.IsType<Run>(inlines[3]).Text);
    }

    [AvaloniaFact]
    public void Convert_BoldAndItalic_StillRendersViaPlaceholders()
    {
        var inlines = Convert("**bold** and *italic*").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("bold", Assert.IsType<Bold>(inlines[0]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" and ", Assert.IsType<Run>(inlines[1]).Text);
        Assert.Equal("italic", Assert.IsType<Italic>(inlines[2]).Inlines.OfType<Run>().First().Text);
    }

    [AvaloniaFact]
    public void Convert_BareUrl_WithOpenUrlCommand_ReturnsClickableButton()
    {
        var command = new RelayCommand<string>(_ => { });
        var inlines = _converter.Convert("See https://example.com for details.", url => command).ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("See ", Assert.IsType<Run>(inlines[0]).Text);
        var container = Assert.IsType<InlineUIContainer>(inlines[1]);
        var button = Assert.IsType<Button>(container.Child);
        Assert.Equal(command, button.Command);
        Assert.Equal("https://example.com", button.CommandParameter);
        Assert.Equal("https://example.com", Assert.IsType<TextBlock>(button.Content).Text);
    }

    [AvaloniaFact]
    public void Convert_MarkdownLink_WithOpenUrlCommand_ReturnsClickableButtonWithText()
    {
        var command = new RelayCommand<string>(_ => { });
        var inlines = _converter.Convert("[docs](https://example.com)", url => command).ToList();

        var container = Assert.IsType<InlineUIContainer>(Assert.Single(inlines));
        var button = Assert.IsType<Button>(container.Child);
        Assert.Equal(command, button.Command);
        Assert.Equal("https://example.com", button.CommandParameter);
        Assert.Equal("docs", Assert.IsType<TextBlock>(button.Content).Text);
    }

    [AvaloniaFact]
    public void Convert_Url_WithoutOpenUrlCommand_ReturnsNonClickableSpan()
    {
        var inlines = Convert("See https://example.com for details.").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.IsType<Span>(inlines[1]);
    }

    [AvaloniaFact]
    public void Convert_BareUrl_WithQueryString_KeepsQueryString()
    {
        var inlines = Convert("See https://example.com/path?q=1&r=2 for details.").ToList();

        var span = Assert.IsType<Span>(inlines[1]);
        Assert.Equal("https://example.com/path?q=1&r=2", span.Inlines.OfType<Run>().First().Text);
    }

    [AvaloniaFact]
    public void Convert_BareUrl_WithPort_KeepsPort()
    {
        var inlines = Convert("See https://example.com:8443/x for details.").ToList();

        var span = Assert.IsType<Span>(inlines[1]);
        Assert.Equal("https://example.com:8443/x", span.Inlines.OfType<Run>().First().Text);
    }

    [AvaloniaFact]
    public void Convert_BareUrl_WithTrailingDot_StripsTrailingDot()
    {
        var inlines = Convert("See https://example.com.").ToList();

        var span = Assert.IsType<Span>(inlines[1]);
        Assert.Equal("https://example.com", span.Inlines.OfType<Run>().First().Text);
    }

    [AvaloniaFact]
    public void Convert_BoldContainsUrl_RendersUrlInsideBold()
    {
        var inlines = Convert("**see https://example.com now**").ToList();

        var bold = Assert.IsType<Bold>(Assert.Single(inlines));
        var children = bold.Inlines!.Cast<Inline>().ToList();
        Assert.Equal(3, children.Count);
        Assert.Equal("see ", Assert.IsType<Run>(children[0]).Text);
        Assert.Equal("https://example.com", Assert.IsType<Span>(children[1]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" now", Assert.IsType<Run>(children[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_BoldContainsInlineCode_RendersCodeInsideBold()
    {
        var inlines = Convert("**run `sudo ufw` now**").ToList();

        var bold = Assert.IsType<Bold>(Assert.Single(inlines));
        var children = bold.Inlines!.Cast<Inline>().ToList();
        Assert.Equal(3, children.Count);
        Assert.Equal("run ", Assert.IsType<Run>(children[0]).Text);
        Assert.IsType<InlineUIContainer>(children[1]);
        Assert.Equal(" now", Assert.IsType<Run>(children[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_BoldContainsItalic_RendersItalicInsideBold()
    {
        var inlines = Convert("**bold *italic* end**").ToList();

        var bold = Assert.IsType<Bold>(Assert.Single(inlines));
        var children = bold.Inlines!.Cast<Inline>().ToList();
        Assert.Equal(3, children.Count);
        Assert.Equal("bold ", Assert.IsType<Run>(children[0]).Text);
        Assert.Equal("italic", Assert.IsType<Italic>(children[1]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" end", Assert.IsType<Run>(children[2]).Text);
    }

    [AvaloniaFact]
    public void Convert_ItalicContainsBold_RendersBoldInsideItalic()
    {
        var inlines = Convert("*text **bold** more*").ToList();

        var italic = Assert.IsType<Italic>(Assert.Single(inlines));
        var children = italic.Inlines!.Cast<Inline>().ToList();
        Assert.Equal(3, children.Count);
        Assert.Equal("text ", Assert.IsType<Run>(children[0]).Text);
        Assert.Equal("bold", Assert.IsType<Bold>(children[1]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" more", Assert.IsType<Run>(children[2]).Text);
    }

    private IEnumerable<Inline> Convert(string text)
    {
        var result = _converter.Convert(text, typeof(object), null, CultureInfo.InvariantCulture);
        return (IEnumerable<Inline>)result;
    }
}
