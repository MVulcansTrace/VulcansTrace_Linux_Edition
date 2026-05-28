using System.Text.Json;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class JsonFormatterTests
{
    private readonly JsonFormatter _formatter = new();

    private static AnalysisResult ResultWith(params Finding[] findings) => new()
    {
        TotalLines = findings.Length,
        ParsedLines = findings.Length,
        Findings = findings,
        Warnings = findings.Length > 0 ? new[] { "Sample warning" } : Array.Empty<string>()
    };

    [Fact]
    public void Format_ContainsMetadataAndFindings()
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
            Details = "20 distinct destinations"
        });

        var json = _formatter.Format(result, "raw log");
        var doc = JsonDocument.Parse(json);

        var root = doc.RootElement;

        // Metadata
        Assert.True(root.TryGetProperty("metadata", out var metadata));
        Assert.Equal("VulcansTrace Linux Edition", metadata.GetProperty("toolName").GetString());
        Assert.Equal(1, metadata.GetProperty("originalLogLines").GetInt32());

        // Findings
        Assert.True(root.TryGetProperty("findings", out var findings));
        Assert.Single(findings.EnumerateArray());
        var f = findings[0];
        Assert.Equal("PortScan", f.GetProperty("category").GetString());
        Assert.Equal("High", f.GetProperty("severity").GetString());
        Assert.Equal("192.168.1.10", f.GetProperty("sourceHost").GetString());
    }

    [Fact]
    public void Format_WithExportTimestamp_UsesProvidedTimestamp()
    {
        var result = ResultWith();
        var timestamp = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        var json = _formatter.Format(result, "raw log", timestamp);
        var doc = JsonDocument.Parse(json);

        var actual = doc.RootElement.GetProperty("metadata").GetProperty("exportTimestamp").GetDateTime();
        Assert.Equal(timestamp, actual);
    }

    [Fact]
    public void Format_EmptyFindings_ProducesValidJson()
    {
        var result = new AnalysisResult
        {
            TotalLines = 0,
            ParsedLines = 0,
            Findings = Array.Empty<Finding>()
        };

        var json = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(json);

        Assert.True(doc.RootElement.TryGetProperty("findings", out var findings));
        Assert.Equal(0, findings.GetArrayLength());
    }

    [Fact]
    public void Format_UsesCamelCaseNaming()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "desc",
            Details = "details"
        });

        var json = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(json);

        // JSON should use camelCase per JsonFormatter's JsonSerializerOptions
        Assert.True(doc.RootElement.TryGetProperty("metadata", out _));
        Assert.True(doc.RootElement.TryGetProperty("findings", out _));

        var finding = doc.RootElement.GetProperty("findings")[0];
        Assert.True(finding.TryGetProperty("sourceHost", out _));
        Assert.True(finding.TryGetProperty("shortDescription", out _));
    }

    [Fact]
    public void Format_IncludesWarnings()
    {
        var result = ResultWith(new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "desc",
            Details = "details"
        });

        var json = _formatter.Format(result, "log");
        var doc = JsonDocument.Parse(json);

        Assert.True(doc.RootElement.TryGetProperty("warnings", out var warnings));
        Assert.Equal(1, warnings.GetArrayLength());
        Assert.Equal("Sample warning", warnings[0].GetString());
    }

    [Fact]
    public void Format_FindingIdIsSerialized()
    {
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Info,
            SourceHost = "10.0.0.1",
            Target = "target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "desc",
            Details = "details"
        };

        var result = ResultWith(finding);
        var json = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(json);

        var f = doc.RootElement.GetProperty("findings")[0];
        Assert.True(f.TryGetProperty("id", out var id));
        Assert.Equal(finding.Id.ToString(), id.GetString());
    }
}
