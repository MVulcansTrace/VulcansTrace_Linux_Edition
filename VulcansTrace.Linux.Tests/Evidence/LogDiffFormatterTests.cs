using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.LogDiff;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class LogDiffFormatterTests
{
    private static readonly DateTime BaseTime = new(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void MarkdownFormatter_ContainsAddedMarker()
    {
        var formatter = new LogDiffMarkdownFormatter();
        var result = CreateSampleResult();

        var markdown = formatter.ToMarkdown(result);

        Assert.Contains("🟥 +", markdown);
    }

    [Fact]
    public void MarkdownFormatter_ContainsRemovedMarker()
    {
        var formatter = new LogDiffMarkdownFormatter();
        var result = CreateSampleResult();

        var markdown = formatter.ToMarkdown(result);

        Assert.Contains("🟩 −", markdown);
    }

    [Fact]
    public void HtmlFormatter_ContainsAddedCssClass()
    {
        var formatter = new LogDiffHtmlFormatter();
        var result = CreateSampleResult();

        var html = formatter.ToHtml(result);

        Assert.Contains("class=\"added\"", html);
        Assert.Contains("+ Added", html);
    }

    [Fact]
    public void HtmlFormatter_ContainsRemovedCssClass()
    {
        var formatter = new LogDiffHtmlFormatter();
        var result = CreateSampleResult();

        var html = formatter.ToHtml(result);

        Assert.Contains("class=\"removed\"", html);
        Assert.Contains("− Removed", html);
    }

    [Fact]
    public void HtmlFormatter_ContainsChangedCssClass()
    {
        var formatter = new LogDiffHtmlFormatter();
        var result = CreateSampleResult();

        var html = formatter.ToHtml(result);

        Assert.Contains("class=\"changed\"", html);
        Assert.Contains("~ Changed", html);
    }

    [Fact]
    public void HtmlFormatter_ContainsUnchangedCssClass()
    {
        var formatter = new LogDiffHtmlFormatter();
        var result = CreateSampleResult();

        var html = formatter.ToHtml(result);

        Assert.Contains("class=\"unchanged\"", html);
        Assert.Contains("= Unchanged", html);
    }

    [Fact]
    public void HtmlFormatter_IsCompleteDocument()
    {
        var formatter = new LogDiffHtmlFormatter();
        var result = CreateSampleResult();

        var html = formatter.ToHtml(result);

        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.EndsWith("</html>", html.Trim());
    }

    [Fact]
    public void MarkdownFormatter_EscapesPipeCharacters()
    {
        var formatter = new LogDiffMarkdownFormatter();
        var result = new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new()
                {
                    ConnectionKey = "a|b",
                    State = LogDiffState.Added,
                    BaselineCount = 0,
                    IncidentCount = 1,
                    SourceIP = "10.0.0.1",
                    DestinationIP = "192.168.1|1",
                    SourcePort = 80,
                    DestinationPort = 443,
                    Protocol = "TCP"
                }
            }
        };

        var markdown = formatter.ToMarkdown(result);

        Assert.DoesNotContain("a|b", markdown);
        Assert.Contains("a\\|b", markdown);
    }

    private static LogDiffResult CreateSampleResult()
    {
        return new LogDiffResult
        {
            Events = new List<DiffEvent>
            {
                new()
                {
                    ConnectionKey = "10.0.0.1:*-192.168.1.1:443-TCP",
                    State = LogDiffState.Added,
                    BaselineCount = 0,
                    IncidentCount = 5,
                    SourceIP = "10.0.0.1",
                    DestinationIP = "192.168.1.1",
                    SourcePort = 80,
                    DestinationPort = 443,
                    Protocol = "TCP",
                    IncidentFirstSeen = BaseTime,
                    IncidentLastSeen = BaseTime.AddMinutes(5)
                },
                new()
                {
                    ConnectionKey = "10.0.0.2:*-192.168.1.1:2222-TCP",
                    State = LogDiffState.Removed,
                    BaselineCount = 3,
                    IncidentCount = 0,
                    SourceIP = "10.0.0.2",
                    DestinationIP = "192.168.1.1",
                    SourcePort = 22,
                    DestinationPort = 2222,
                    Protocol = "TCP",
                    BaselineFirstSeen = BaseTime,
                    BaselineLastSeen = BaseTime.AddMinutes(2)
                },
                new()
                {
                    ConnectionKey = "10.0.0.3:*-192.168.1.1:54321-TCP",
                    State = LogDiffState.Changed,
                    BaselineCount = 2,
                    IncidentCount = 10,
                    SourceIP = "10.0.0.3",
                    DestinationIP = "192.168.1.1",
                    SourcePort = 443,
                    DestinationPort = 54321,
                    Protocol = "TCP",
                    BaselineFirstSeen = BaseTime,
                    BaselineLastSeen = BaseTime.AddMinutes(1),
                    IncidentFirstSeen = BaseTime.AddHours(1),
                    IncidentLastSeen = BaseTime.AddHours(1).AddMinutes(5)
                },
                new()
                {
                    ConnectionKey = "10.0.0.4:*-192.168.1.1:12345-UDP",
                    State = LogDiffState.Unchanged,
                    BaselineCount = 4,
                    IncidentCount = 4,
                    SourceIP = "10.0.0.4",
                    DestinationIP = "192.168.1.1",
                    SourcePort = 53,
                    DestinationPort = 12345,
                    Protocol = "UDP",
                    BaselineFirstSeen = BaseTime,
                    BaselineLastSeen = BaseTime.AddMinutes(3),
                    IncidentFirstSeen = BaseTime.AddHours(2),
                    IncidentLastSeen = BaseTime.AddHours(2).AddMinutes(3)
                }
            },
            Findings = new List<DiffFinding>
            {
                new()
                {
                    Finding = new Finding
                    {
                        Category = FindingCategories.PortScan,
                        Severity = Severity.High,
                        SourceHost = "10.0.0.1",
                        Target = "192.168.1.1:443",
                        TimeRangeStart = BaseTime,
                        TimeRangeEnd = BaseTime.AddMinutes(5),
                        ShortDescription = "Port scan detected",
                        Details = "Details"
                    },
                    State = LogDiffState.Added
                }
            },
            BaselineTimeRangeStart = BaseTime,
            BaselineTimeRangeEnd = BaseTime.AddHours(1),
            IncidentTimeRangeStart = BaseTime.AddHours(1),
            IncidentTimeRangeEnd = BaseTime.AddHours(2)
        };
    }
}
