using System.Globalization;
using System.Linq;
using Avalonia.Controls.Documents;
using VulcansTrace.Linux.Avalonia.Converters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class MarkdownInlinesConverterTests
{
    private readonly MarkdownInlinesConverter _converter = new();

    [Fact]
    public void Convert_PlainText_ReturnsSingleRun()
    {
        var inlines = Convert("Hello world");

        var run = Assert.Single(inlines.OfType<Run>());
        Assert.Equal("Hello world", run.Text);
    }

    [Fact]
    public void Convert_BoldText_ReturnsBoldRun()
    {
        var inlines = Convert("**Hello**");

        var bold = Assert.Single(inlines.OfType<Bold>());
        var run = Assert.Single(bold.Inlines.OfType<Run>());
        Assert.Equal("Hello", run.Text);
    }



    [Fact]
    public void Convert_MixedContent_ReturnsRunsAndBold()
    {
        var inlines = Convert("Hello **bold** world").ToList();

        Assert.Equal(3, inlines.Count);
        Assert.Equal("Hello ", Assert.IsType<Run>(inlines[0]).Text);
        Assert.Equal("bold", Assert.IsType<Bold>(inlines[1]).Inlines.OfType<Run>().First().Text);
        Assert.Equal(" world", Assert.IsType<Run>(inlines[2]).Text);
    }

    [Fact]
    public void Convert_ParagraphBreak_ReturnsTwoLineBreaks()
    {
        var inlines = Convert("Line one\n\nLine two").ToList();

        var lineBreaks = inlines.OfType<LineBreak>().Count();
        Assert.Equal(2, lineBreaks);
    }

    [Fact]
    public void Convert_EmptyString_ReturnsEmpty()
    {
        var inlines = Convert("");

        Assert.Empty(inlines);
    }

    [Fact]
    public void Convert_Null_ReturnsEmpty()
    {
        var result = _converter.Convert(null, typeof(object), null, CultureInfo.InvariantCulture);

        Assert.Empty((System.Collections.IEnumerable)result);
    }

    [Fact]
    public void Convert_ItalicText_ReturnsItalicRun()
    {
        var inlines = Convert("*Hello*");

        var italic = Assert.Single(inlines.OfType<Italic>());
        var run = Assert.Single(italic.Inlines.OfType<Run>());
        Assert.Equal("Hello", run.Text);
    }

    [Fact]
    public void Convert_SnakeCase_PreservedAsPlainText()
    {
        var inlines = Convert("file_name_here and /path/to_some/file").ToList();

        Assert.All(inlines, inline => Assert.IsType<Run>(inline));
        var text = string.Join("", inlines.OfType<Run>().Select(r => r.Text));
        Assert.Equal("file_name_here and /path/to_some/file", text);
    }

    [Fact]
    public void Convert_Underscore_NoLongerTreatedAsItalic()
    {
        var inlines = Convert("_Hello_").ToList();

        Assert.Single(inlines);
        Assert.Equal("_Hello_", Assert.IsType<Run>(inlines[0]).Text);
    }

    private IEnumerable<Inline> Convert(string text)
    {
        var result = _converter.Convert(text, typeof(object), null, CultureInfo.InvariantCulture);
        return (IEnumerable<Inline>)result;
    }
}
