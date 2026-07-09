using System.Text.Json;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class MispFormatterTests
{
    private readonly MispFormatter _formatter = new();

    private static AnalysisResult ResultWith(params Finding[] findings) => new()
    {
        TotalLines = findings.Length,
        ParsedLines = findings.Length,
        Findings = findings
    };

    [Fact]
    public void Format_IpBasedFinding_ProducesIpAttributes()
    {
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:80",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Port scan detected",
            Details = "20 distinct destinations",
            RuleId = "PORT-001"
        });

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var attributes = doc.RootElement.GetProperty("Event").GetProperty("Attribute").EnumerateArray().ToList();

        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "ip-src" && a.GetProperty("value").GetString() == "192.168.1.10");
        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "ip-dst" && a.GetProperty("value").GetString() == "10.0.0.5");
        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "port" && a.GetProperty("value").GetString() == "80");
    }

    [Fact]
    public void Format_NonIpFinding_ProducesTextAttribute()
    {
        var result = ResultWith(new Finding
        {
            Category = "KernelModule",
            Severity = Severity.Info,
            SourceHost = "Firewall Configuration",
            Target = "Connection Tracking (conntrack)",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Detected Connection Tracking (conntrack)",
            Details = "Analysis indicates the use of conntrack."
        });

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var attributes = doc.RootElement.GetProperty("Event").GetProperty("Attribute").EnumerateArray().ToList();

        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "text");
    }

    [Fact]
    public void Format_IncludesThreatLevel()
    {
        var result = ResultWith(new Finding
        {
            Category = "C2Channel",
            Severity = Severity.Critical,
            SourceHost = "192.168.1.50",
            Target = "203.0.113.10:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddHours(1),
            ShortDescription = "Potential C2 channel detected",
            Details = "Periodic communication pattern"
        });

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var threatLevel = doc.RootElement.GetProperty("Event").GetProperty("threat_level_id").GetString();

        Assert.Equal("1", threatLevel);
    }

    [Fact]
    public void Format_MixedSeverities_ThreatLevelReflectsMostSevere()
    {
        // A bundle containing a Critical finding must export threat_level_id "1" (High), even when
        // less-severe findings are also present (regression: the index lookup used Max, not Min).
        var result = ResultWith(
            new Finding
            {
                Category = "LowCat",
                Severity = Severity.Info,
                SourceHost = "1.1.1.1",
                Target = "2.2.2.2",
                TimeRangeStart = DateTime.UnixEpoch,
                TimeRangeEnd = DateTime.UnixEpoch
            },
            new Finding
            {
                Category = "HighCat",
                Severity = Severity.Critical,
                SourceHost = "3.3.3.3",
                Target = "4.4.4.4",
                TimeRangeStart = DateTime.UnixEpoch,
                TimeRangeEnd = DateTime.UnixEpoch
            });

        var misp = _formatter.Format(result, "");
        var threatLevel = JsonDocument.Parse(misp).RootElement.GetProperty("Event").GetProperty("threat_level_id").GetString();

        Assert.Equal("1", threatLevel);
    }

    [Fact]
    public void Format_SourceIpWithoutTarget_DoesNotEmitRedundantText()
    {
        // A finding with a valid source IP but a non-IP target emits ip-src only; the text
        // fallback must not also fire (regression: it duplicated the finding as a text attribute).
        var result = ResultWith(new Finding
        {
            Category = "X",
            Severity = Severity.High,
            SourceHost = "10.0.0.5",
            Target = "myhost.example.com",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "odd finding"
        });

        var attributes = JsonDocument.Parse(_formatter.Format(result, "")).RootElement.GetProperty("Event").GetProperty("Attribute").EnumerateArray().ToList();

        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "ip-src" && a.GetProperty("value").GetString() == "10.0.0.5");
        Assert.DoesNotContain(attributes, a => a.GetProperty("type").GetString() == "text");
    }

    [Fact]
    public void Format_EmptyFindings_ProducesEmptyAttributes()
    {
        var result = new AnalysisResult
        {
            TotalLines = 0,
            ParsedLines = 0,
            Findings = Array.Empty<Finding>()
        };

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var evt = doc.RootElement.GetProperty("Event");

        Assert.Equal("VulcansTrace analysis export", evt.GetProperty("info").GetString());
        // No findings => MISP threat_level_id 4 (undefined), not the default "3" (low).
        Assert.Equal("4", evt.GetProperty("threat_level_id").GetString());
        Assert.Empty(evt.GetProperty("Attribute").EnumerateArray());
    }

    [Fact]
    public void Format_IncludesEventMetadataAndAttributeCategoryToIds()
    {
        // External MISP instances reject events/attributes missing required fields, so the export
        // must carry distribution/analysis/date at the event level and category/to_ids per attribute.
        var exportTime = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var result = ResultWith(new Finding
        {
            Category = "C2Channel",
            Severity = Severity.High,
            SourceHost = "192.168.1.50",
            Target = "203.0.113.10:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddHours(1),
            ShortDescription = "Potential C2 channel detected",
            Details = "Periodic communication pattern"
        });

        var evt = JsonDocument.Parse(_formatter.Format(result, "", exportTime)).RootElement.GetProperty("Event");

        Assert.Equal("0", evt.GetProperty("distribution").GetString());
        Assert.Equal("0", evt.GetProperty("analysis").GetString());
        Assert.Equal("2024-06-15", evt.GetProperty("date").GetString());

        // IPs are actionable indicators -> to_ids true; a bare port is not -> to_ids false.
        var ipSrc = evt.GetProperty("Attribute").EnumerateArray()
            .First(a => a.GetProperty("type").GetString() == "ip-src");
        Assert.Equal("Network activity", ipSrc.GetProperty("category").GetString());
        Assert.True(ipSrc.GetProperty("to_ids").GetBoolean());

        var port = evt.GetProperty("Attribute").EnumerateArray()
            .First(a => a.GetProperty("type").GetString() == "port");
        Assert.Equal("Network activity", port.GetProperty("category").GetString());
        Assert.False(port.GetProperty("to_ids").GetBoolean());
    }

    [Fact]
    public void Format_CanBeParsedByMispParser()
    {
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Medium,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.5:4444",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(10),
            ShortDescription = "Regular beaconing",
            Details = "60s intervals"
        });

        var misp = _formatter.Format(result, "");
        var importResult = MispParser.Parse(misp);

        Assert.True(importResult.ImportedCount >= 2, $"Expected at least 2 IOCs, got {importResult.ImportedCount}");
        Assert.Contains(importResult.Entries, e => e.Type == IocType.IPv4 && e.Value == "192.168.1.100");
        Assert.Contains(importResult.Entries, e => e.Type == IocType.IPv4 && e.Value == "10.0.0.5");
        Assert.Contains(importResult.Entries, e => e.Type == IocType.Port && e.Value == "4444");
    }

    [Fact]
    public void Format_BracketedIpv6WithPort_ExtractsIpAndPort()
    {
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "[2001:db8::1]:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Port scan",
            Details = "Scanned ports"
        });

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var attributes = doc.RootElement.GetProperty("Event").GetProperty("Attribute").EnumerateArray().ToList();

        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "ip-dst" && a.GetProperty("value").GetString() == "2001:db8::1");
        Assert.Contains(attributes, a => a.GetProperty("type").GetString() == "port" && a.GetProperty("value").GetString() == "443");
    }

    [Fact]
    public void Format_IncludesTags()
    {
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Critical,
            SourceHost = "10.0.0.1",
            Target = "8.8.8.8",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch,
            ShortDescription = "Beaconing detected",
            Details = "Periodic outbound traffic",
            MitreTechniques =
            [
                new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Web Protocols", Tactic = "Command and Control" }
            ]
        });

        var misp = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(misp);
        var attribute = doc.RootElement.GetProperty("Event").GetProperty("Attribute").EnumerateArray().First();
        var tags = attribute.GetProperty("Tag").EnumerateArray().Select(t => t.GetProperty("name").GetString()).ToList();

        Assert.Contains("category:Beaconing", tags);
        Assert.Contains("severity:Critical", tags);
        Assert.Contains("mitre-attack:T1071.001", tags);
    }
}
