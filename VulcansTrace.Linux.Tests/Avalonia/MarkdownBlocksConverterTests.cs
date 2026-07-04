using System.Linq;
using Avalonia.Controls.Documents;
using VulcansTrace.Linux.Avalonia.Converters;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MarkdownBlocksConverterTests
{
    private readonly MarkdownBlocksConverter _converter = new();

    [AvaloniaFact]
    public void Parse_EmptyText_ReturnsEmptyBlocks()
    {
        var blocks = _converter.Parse("", _ => new RelayCommand(_ => { }));

        Assert.Empty(blocks);
    }

    [AvaloniaFact]
    public void Parse_FencedCodeBlock_ReturnsCodeBlock()
    {
        var blocks = _converter.Parse("```bash\nsudo ufw status\n```", _ => new RelayCommand(_ => { }));

        var codeBlock = Assert.Single(blocks.OfType<CodeBlock>());
        Assert.Equal("bash", codeBlock.Language);
        Assert.Equal("sudo ufw status", codeBlock.Code);
        Assert.True(codeBlock.IsExpanded);
        Assert.NotNull(codeBlock.ToggleExpandCommand);
        Assert.NotNull(codeBlock.CopyCommand);
    }

    [AvaloniaFact]
    public void Parse_CodeBlockWithoutLanguage_ReturnsCodeBlockWithEmptyLanguage()
    {
        var blocks = _converter.Parse("```\nsudo ufw status\n```", _ => new RelayCommand(_ => { }));

        var codeBlock = Assert.Single(blocks.OfType<CodeBlock>());
        Assert.Empty(codeBlock.Language);
        Assert.Equal("sudo ufw status", codeBlock.Code);
    }

    [AvaloniaFact]
    public void Parse_ProseAndCode_ReturnsParagraphThenCode()
    {
        var text = "Run this command:\n\n```bash\nsudo ufw status\n```";
        var blocks = _converter.Parse(text, _ => new RelayCommand(_ => { }));

        Assert.Equal(2, blocks.Count);
        Assert.IsType<ParagraphBlock>(blocks[0]);
        var codeBlock = Assert.IsType<CodeBlock>(blocks[1]);
        Assert.Equal("bash", codeBlock.Language);
    }

    [AvaloniaFact]
    public void Parse_BulletList_RendersBulletPrefix()
    {
        var text = "First line\n\n- item one\n- item two";
        var blocks = _converter.Parse(text, _ => new RelayCommand(_ => { }));

        var paragraph = Assert.IsType<ParagraphBlock>(blocks[1]);
        var inlines = paragraph.Inlines.Cast<Inline>().ToList();
        var textRuns = string.Join("", inlines.OfType<Run>().Select(r => r.Text));
        Assert.Contains("• item one", textRuns);
        Assert.Contains("• item two", textRuns);
    }

    [AvaloniaFact]
    public void Parse_NumberedList_RendersNormalizedPrefix()
    {
        var text = "First line\n\n9. item one\n3. item two";
        var blocks = _converter.Parse(text, _ => new RelayCommand(_ => { }));

        var paragraph = Assert.IsType<ParagraphBlock>(blocks[1]);
        var inlines = paragraph.Inlines.Cast<Inline>().ToList();
        var textRuns = string.Join("", inlines.OfType<Run>().Select(r => r.Text));
        Assert.Contains("1.  item one", textRuns);
        Assert.Contains("2.  item two", textRuns);
    }

    [AvaloniaFact]
    public void Parse_MixedList_RendersBothPrefixes()
    {
        var text = "- bullet\n1. numbered";
        var blocks = _converter.Parse(text, _ => new RelayCommand(_ => { }));

        var paragraph = Assert.IsType<ParagraphBlock>(Assert.Single(blocks));
        var inlines = paragraph.Inlines.Cast<Inline>().ToList();
        var textRuns = string.Join("", inlines.OfType<Run>().Select(r => r.Text));
        Assert.Contains("• bullet", textRuns);
        Assert.Contains("1.  numbered", textRuns);
    }

    [AvaloniaFact]
    public void Parse_CodeBlock_ToggleCommandChangesIsExpanded()
    {
        var blocks = _converter.Parse("```bash\nsudo ufw status\n```", _ => new RelayCommand(_ => { }));
        var codeBlock = Assert.Single(blocks.OfType<CodeBlock>());

        codeBlock.ToggleExpandCommand.Execute(null);

        Assert.False(codeBlock.IsExpanded);
    }
}
