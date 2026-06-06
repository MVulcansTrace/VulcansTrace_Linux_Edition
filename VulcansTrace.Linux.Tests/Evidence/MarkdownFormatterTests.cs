using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class MarkdownFormatterTests
{
    private readonly MarkdownFormatter _formatter = new();

    private static AnalysisResult ResultWith(params Finding[] findings) => new()
    {
        TotalLines = findings.Length,
        ParsedLines = findings.Length,
        Findings = findings
    };

    [Fact]
    public void ToMarkdown_ContainsHeaderAndColumns()
    {
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:80",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "20 distinct destinations",
            RuleId = "PORT-001"
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("# VulcansTrace Analysis Summary", md);
        Assert.Contains("| Rule ID | Category |", md);
        Assert.Contains("| CIS Control |", md);
        Assert.Contains("PortScan", md);
        Assert.Contains("PORT-001", md);
        Assert.Contains("192.168.1.10", md);
    }

    [Fact]
    public void ToMarkdown_EscapesPipeCharacters()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target|with|pipes",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "desc",
            Details = "details"
        });

        var md = _formatter.ToMarkdown(result);

        // Pipes in values should be escaped, not breaking the table
        Assert.Contains(@"\|", md);
        Assert.DoesNotContain("target|with|pipes", md);
    }

    [Fact]
    public void ToMarkdown_EscapesNewlines()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "line1\nline2",
            Details = "details"
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("line1 / line2", md);
        Assert.DoesNotContain("<br>", md);
    }

    [Fact]
    public void ToMarkdown_EmptyFindings_ShowsTableHeader()
    {
        var result = new AnalysisResult
        {
            TotalLines = 0,
            ParsedLines = 0,
            Findings = Array.Empty<Finding>()
        };

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("# VulcansTrace Analysis Summary", md);
        Assert.Contains("| Rule ID | Category |", md);
        Assert.Contains("None", md); // Warnings section shows "None"
    }

    [Fact]
    public void ToMarkdown_WarningsAreListed()
    {
        var result = new AnalysisResult
        {
            TotalLines = 2,
            ParsedLines = 2,
            Findings = Array.Empty<Finding>(),
            Warnings = new[] { "Warning one", "Warning two" }
        };

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("Warning one", md);
        Assert.Contains("Warning two", md);
        Assert.Contains("Warnings: 2", md);
    }

    [Fact]
    public void ToMarkdown_EscapesSpecialMarkdownCharacters()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "has *bold* and `code`",
            Details = "details"
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains(@"\*", md);
        Assert.Contains(@"\`", md);
    }

    [Fact]
    public void ToMarkdown_EscapesRawHtml()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "<script>alert(1)</script>",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "has <b>html</b> & entity",
            Details = "details"
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", md);
        Assert.Contains("&lt;b&gt;html&lt;/b&gt; &amp; entity", md);
        Assert.DoesNotContain("<script>", md);
        Assert.DoesNotContain("<b>", md);
    }

    [Fact]
    public void ToMarkdown_SuppressionNotesIncludeFingerprint()
    {
        var result = new AnalysisResult
        {
            Findings = [],
            ActiveSuppressions =
            [
                new SuppressionSummary
                {
                    RuleId = "FW-001",
                    Target = "INPUT",
                    Fingerprint = "fp1",
                    Reason = "Known exposure",
                    CreatedAt = DateTime.UnixEpoch
                }
            ]
        };

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("| Rule ID | Target | Fingerprint |", md);
        Assert.Contains("| FW-001 | INPUT | fp1 | Known exposure |", md);
    }

    [Fact]
    public void ToMarkdown_IncludesCapabilityReport()
    {
        var result = new AnalysisResult
        {
            Findings = [],
            CapabilityReport = "Data sources: iptables available; systemctl permission-limited."
        };

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("## Data Sources", md);
        Assert.Contains("Data sources: iptables available; systemctl permission-limited.", md);
    }

    [Fact]
    public void ToMarkdown_IncludesMitreTechniques()
    {
        var result = ResultWith(new Finding
        {
            Category = "C2Channel",
            Severity = Severity.High,
            SourceHost = "10.0.0.1",
            Target = "8.8.8.8",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "C2 detected",
            Details = "details",
            MitreTechniques =
            [
                new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Web Protocols", Tactic = "Command and Control", WhyItMatters = "C2." }
            ]
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("T1071.001", md);
        Assert.Contains("## MITRE ATT&CK Context", md);
    }

    [Fact]
    public void ToMarkdown_IncludesConfidenceAndEvidenceSignals()
    {
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Critical,
            Confidence = DetectionConfidence.High,
            SourceHost = "10.0.0.1",
            Target = "8.8.8.8",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "Beaconing",
            Details = "details",
            EvidenceSignals =
            [
                new EvidenceSignal { Name = "Periodic outbound traffic", Source = "Behavior", Explanation = "Repeating intervals" }
            ]
        });

        var md = _formatter.ToMarkdown(result);

        Assert.Contains("Confidence", md);
        Assert.Contains("Evidence Signals", md);
        Assert.Contains("High", md);
        Assert.Contains("Periodic outbound traffic", md);
    }
}
