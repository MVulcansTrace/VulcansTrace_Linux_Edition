using System;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Evidence;

public class HtmlFormatterTests
{
    [Fact]
    public void ToHtml_EncodesUserProvidedContent()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = "<script>alert(1)</script>",
                    Severity = Severity.Low,
                    SourceHost = "192.168.1.5",
                    Target = "10.0.0.6",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "<b>bold</b>",
                    Details = "detail",
                    RuleId = "<FW-001>"
                }
            ],
            Warnings = ["<img src=x onerror=alert(1)>"]
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", html);
        Assert.Contains("&lt;b&gt;bold&lt;/b&gt;", html);
        Assert.Contains("&lt;FW-001&gt;", html);
        Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
        Assert.DoesNotContain("<script>alert(1)</script>", html);
    }

    [Fact]
    public void ToHtml_EmptyFindings_ProducesTableHeader()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings = []
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("<th>Rule ID</th>", html);
        Assert.Contains("<th>Category</th>", html);
        Assert.Contains("<th>Severity</th>", html);
        Assert.DoesNotContain("<td>", html);
    }

    [Fact]
    public void ToHtml_EncodesAllUserControlledFields()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = "<cat>",
                    Severity = Severity.High,
                    SourceHost = "<script>src</script>",
                    Target = "<b>target</b>",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch,
                    ShortDescription = "<i>desc</i>",
                    Details = "detail"
                }
            ]
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("&lt;script&gt;src&lt;/script&gt;", html);
        Assert.Contains("&lt;b&gt;target&lt;/b&gt;", html);
        Assert.DoesNotContain("<script>src</script>", html);
        Assert.DoesNotContain("<b>target</b>", html);
    }

    [Fact]
    public void ToHtml_WarningsPresent_IncludedInList()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings = [],
            Warnings = ["warning-one", "warning-two"]
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("warning-one", html);
        Assert.Contains("warning-two", html);
        Assert.Contains("Warnings: 2", html);
    }

    [Fact]
    public void ToHtml_ParseErrors_ShownInSummary()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings = [],
            ParseErrorCount = 3
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("Parse errors: 3", html);
    }

    [Fact]
    public void ToHtml_SuppressionNotesIncludeEncodedFingerprint()
    {
        var formatter = new HtmlFormatter();
        var result = new AnalysisResult
        {
            Findings = [],
            ActiveSuppressions =
            [
                new SuppressionSummary
                {
                    RuleId = "FW-001",
                    Target = "INPUT",
                    Fingerprint = "<fp1>",
                    Reason = "Known exposure",
                    CreatedAt = DateTime.UnixEpoch
                }
            ]
        };

        var html = formatter.ToHtml(result);

        Assert.Contains("<th>Fingerprint</th>", html);
        Assert.Contains("&lt;fp1&gt;", html);
        Assert.DoesNotContain("<fp1>", html);
    }
}
