using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using VulcansTrace.Linux.Avalonia.Converters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

/// <summary>
/// Proves the Markdown attached property wires the converter output into a real TextBlock's
/// Inlines (the feature the docs describe but that was previously never connected to the UI).
/// </summary>
[Collection(AvaloniaUiTestCollection.Name)]
public class MarkdownTextAttachedPropertyTests
{
    [Fact]
    public void SetText_Plain_PopulatesSingleRun()
    {
        var tb = new TextBlock();

        Markdown.SetText(tb, "Hello world");

        var run = Assert.IsType<Run>(Assert.Single(tb.Inlines!));
        Assert.Equal("Hello world", run.Text);
    }

    [Fact]
    public void SetText_Bold_RendersAsBoldInline()
    {
        var tb = new TextBlock();

        Markdown.SetText(tb, "Hello **bold** world");

        var inlines = tb.Inlines!;
        Assert.Equal(3, inlines.Count);
        Assert.IsType<Bold>(inlines[1]);
        var run = Assert.Single(Assert.IsType<Bold>(inlines[1]).Inlines.OfType<Run>());
        Assert.Equal("bold", run.Text);
    }

    [Fact]
    public void SetText_Italic_RendersAsItalicInline()
    {
        var tb = new TextBlock();

        Markdown.SetText(tb, "*note*");

        Assert.IsType<Italic>(Assert.Single(tb.Inlines!));
    }

    [Fact]
    public void SetText_Null_LeavesInlinesEmpty()
    {
        var tb = new TextBlock();

        Markdown.SetText(tb, null);

        Assert.Empty(tb.Inlines!);
    }

    [Fact]
    public void SetText_ReplacesPreviousContent()
    {
        var tb = new TextBlock();

        Markdown.SetText(tb, "**first**");
        Markdown.SetText(tb, "second");

        var run = Assert.IsType<Run>(Assert.Single(tb.Inlines!));
        Assert.Equal("second", run.Text);
    }
}
