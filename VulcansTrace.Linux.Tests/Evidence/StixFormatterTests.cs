using System.Text.Json;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Tests.Evidence;

public class StixFormatterTests
{
    private readonly StixFormatter _formatter = new();

    private static AnalysisResult ResultWith(params Finding[] findings) => new()
    {
        TotalLines = findings.Length,
        ParsedLines = findings.Length,
        Findings = findings
    };

    [Fact]
    public void Format_IpBasedFinding_ProducesObservedDataAndNote()
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

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        // Should contain observed-data, ipv4-addr, note, and identity
        var types = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Select(o => o.TryGetProperty("type", out var t) ? t.GetString() : null)
            .Where(t => t != null)
            .ToList();

        Assert.Contains("identity", types);
        Assert.Contains("ipv4-addr", types);
        Assert.Contains("observed-data", types);
        Assert.Contains("note", types);

        var note = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .First(o => o.GetProperty("type").GetString() == "note");
        Assert.Contains("Rule ID: PORT-001", note.GetProperty("content").GetString());
    }

    [Fact]
    public void Format_WithSameTimestamp_ProducesStableOutput()
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
            Details = "20 distinct destinations"
        });
        var timestamp = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        var first = _formatter.Format(result, "raw log", timestamp);
        var second = _formatter.Format(result, "raw log", timestamp);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Format_KernelModuleFinding_IncludedAsStandaloneNote()
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
            Details = "Analysis of firewall logs indicates the use of Connection Tracking (conntrack)."
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // Should contain a note with the KernelModule content
        var notes = objects
            .Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "note")
            .ToList();

        Assert.NotEmpty(notes);
        var kernelNote = notes.FirstOrDefault(n =>
            n.TryGetProperty("content", out var c) &&
            c.GetString()!.Contains("KernelModule"));

        Assert.True(kernelNote.TryGetProperty("content", out var contentEl));
        Assert.Contains("Connection Tracking", contentEl.GetString());
        Assert.False(kernelNote.TryGetProperty("object_refs", out _));

        // Verify the note has a label matching the category
        Assert.True(kernelNote.TryGetProperty("labels", out var labels));
        Assert.Contains("KernelModule", labels.EnumerateArray().Select(l => l.GetString()));
    }

    [Fact]
    public void Format_C2ChannelFinding_IncludesMalwareObject()
    {
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

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var types = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Select(o => o.TryGetProperty("type", out var t) ? t.GetString() : null)
            .Where(t => t != null)
            .ToList();

        Assert.Contains("malware", types);
    }

    [Fact]
    public void Format_EmptyFindings_ProducesMinimalBundle()
    {
        var result = new AnalysisResult
        {
            TotalLines = 0,
            ParsedLines = 0,
            Findings = Array.Empty<Finding>()
        };

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        Assert.Equal("bundle", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("2.1", doc.RootElement.GetProperty("spec_version").GetString());

        // Should still have the identity object
        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();
        Assert.Single(objects);
        Assert.Equal("identity", objects[0].GetProperty("type").GetString());
    }

    [Fact]
    public void Format_MixedIpAndNonIpFindings_AllIncludedInOutput()
    {
        var result = ResultWith(
            new Finding
            {
                Category = "PortScan",
                Severity = Severity.High,
                SourceHost = "192.168.1.10",
                Target = "10.0.0.5:80",
                TimeRangeStart = DateTime.UnixEpoch,
                TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                ShortDescription = "Port scan",
                Details = "Scanned 20 ports"
            },
            new Finding
            {
                Category = "KernelModule",
                Severity = Severity.Info,
                SourceHost = "Firewall Configuration",
                Target = "IPv6 Support",
                TimeRangeStart = DateTime.UnixEpoch,
                TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                ShortDescription = "Detected IPv6 Support",
                Details = "IPv6 addresses found in logs"
            }
        );

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var notes = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "note")
            .ToList();

        // Both findings should produce notes
        Assert.True(notes.Count >= 2, "Should have notes for both IP-based and non-IP findings");

        var noteContents = notes.Select(n => n.GetProperty("content").GetString()).ToList();
        Assert.Contains(noteContents, c => c!.Contains("PortScan"));
        Assert.Contains(noteContents, c => c!.Contains("KernelModule"));
    }

    [Fact]
    public void Format_Ipv6Finding_ProducesIpv6AddrObject()
    {
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Medium,
            SourceHost = "2001:db8::1",
            Target = "2001:db8::2:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(10),
            ShortDescription = "Regular beaconing",
            Details = "60s intervals"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var types = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Select(o => o.TryGetProperty("type", out var t) ? t.GetString() : null)
            .Where(t => t != null)
            .ToList();

        Assert.Contains("ipv6-addr", types);
    }

    [Fact]
    public void Format_BracketedIpv6WithPort_ExtractsIpCorrectly()
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

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // Should contain ipv6-addr for the bracketed target
        var ipv6Addrs = objects.Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "ipv6-addr").ToList();
        Assert.Single(ipv6Addrs);
        Assert.Equal("2001:db8::1", ipv6Addrs[0].GetProperty("value").GetString());
    }

    [Fact]
    public void Format_InvalidBracketedIpv6_EmitsStandaloneNote()
    {
        var result = ResultWith(new Finding
        {
            Category = "KernelModule",
            Severity = Severity.Info,
            SourceHost = "not-an-ip",
            Target = "[not-an-ip]:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Module load",
            Details = "Loaded module"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // Both source and target are invalid IPs → standalone note only, no observed-data
        Assert.DoesNotContain(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");
        Assert.Contains(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "note");
    }

    [Fact]
    public void Format_EmptyBrackets_EmitsStandaloneNote()
    {
        var result = ResultWith(new Finding
        {
            Category = "KernelModule",
            Severity = Severity.Info,
            SourceHost = "not-an-ip",
            Target = "[]:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Module load",
            Details = "Loaded module"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // Empty brackets → bracketEnd = 1, fails > 1 check → null → standalone note
        Assert.DoesNotContain(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");
        Assert.Contains(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "note");
    }

    [Fact]
    public void Format_ColonButInvalidIp_ExtractsFromWholeString()
    {
        // "2001:db8::1" has no port but has colons; whole-string TryParse should succeed
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Medium,
            SourceHost = "192.168.1.10",
            Target = "2001:db8::1",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(10),
            ShortDescription = "Beacon",
            Details = "Periodic"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();
        var ipv6Addrs = objects.Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "ipv6-addr").ToList();

        Assert.Single(ipv6Addrs);
        Assert.Equal("2001:db8::1", ipv6Addrs[0].GetProperty("value").GetString());
    }

    [Fact]
    public void Format_NonIpTargetWithColon_EmitsStandaloneNote()
    {
        var result = ResultWith(new Finding
        {
            Category = "KernelModule",
            Severity = Severity.Info,
            SourceHost = "not-an-ip",
            Target = "some-host:123",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Module load",
            Details = "Loaded module"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // some-host:123 → lastColon > 0, candidate "some-host" fails TryParse,
        // whole string "some-host:123" also fails TryParse → null
        Assert.DoesNotContain(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");
        Assert.Contains(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "note");
    }

    [Fact]
    public void Format_LocalKindTime_NormalizesToUtc()
    {
        var localTime = new DateTime(2023, 6, 15, 10, 0, 0, DateTimeKind.Local);
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5",
            TimeRangeStart = localTime,
            TimeRangeEnd = localTime.AddMinutes(5),
            ShortDescription = "Port scan",
            Details = "Scanned ports"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var observedData = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .First(o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");

        var firstObserved = observedData.GetProperty("first_observed").GetDateTime();
        var lastObserved = observedData.GetProperty("last_observed").GetDateTime();

        // Local time should have been converted to UTC
        Assert.Equal(DateTimeKind.Utc, firstObserved.Kind);
        Assert.Equal(DateTimeKind.Utc, lastObserved.Kind);
        // The values should reflect the UTC conversion (local 10:00 → UTC depends on timezone offset)
        Assert.Equal(localTime.ToUniversalTime(), firstObserved);
    }

    [Fact]
    public void Format_UnspecifiedKindTime_SpecifiesUtc()
    {
        var unspecifiedTime = new DateTime(2023, 6, 15, 10, 0, 0, DateTimeKind.Unspecified);
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5",
            TimeRangeStart = unspecifiedTime,
            TimeRangeEnd = unspecifiedTime.AddMinutes(5),
            ShortDescription = "Port scan",
            Details = "Scanned ports"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var observedData = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .First(o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");

        var firstObserved = observedData.GetProperty("first_observed").GetDateTime();
        var lastObserved = observedData.GetProperty("last_observed").GetDateTime();

        // Unspecified time should be treated as UTC with same value
        Assert.Equal(DateTimeKind.Utc, firstObserved.Kind);
        Assert.Equal(unspecifiedTime, firstObserved);
        Assert.Equal(DateTimeKind.Utc, lastObserved.Kind);
        Assert.Equal(unspecifiedTime.AddMinutes(5), lastObserved);
    }

    [Fact]
    public void Format_FindingWithEmptyTarget_EmitsStandaloneNote()
    {
        // Finding.Target defaults to string.Empty if not set, which triggers
        // ExtractTargetIp's whitespace-only branch (defensive coding).
        var result = ResultWith(new Finding
        {
            Category = "KernelModule",
            Severity = Severity.Info,
            SourceHost = "not-an-ip",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Module load",
            Details = "Loaded module"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();

        // Both source and target are invalid IPs → standalone note only
        Assert.DoesNotContain(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");
        Assert.Contains(objects, o => o.TryGetProperty("type", out var t) && t.GetString() == "note");
    }

    [Fact]
    public void Format_MinValueTime_UsesFallback()
    {
        var result = ResultWith(new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5",
            TimeRangeStart = DateTime.MinValue,
            TimeRangeEnd = DateTime.MinValue,
            ShortDescription = "Port scan",
            Details = "Scanned ports"
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var observedData = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .First(o => o.TryGetProperty("type", out var t) && t.GetString() == "observed-data");

        var firstObserved = observedData.GetProperty("first_observed").GetDateTime();
        var lastObserved = observedData.GetProperty("last_observed").GetDateTime();

        // MinValue should fall back to 'now' (both are MinValue, so lastObserved falls back to firstObserved,
        // which falls back to DateTime.UtcNow from the Format method)
        Assert.NotEqual(DateTime.MinValue, firstObserved);
        Assert.NotEqual(DateTime.MinValue, lastObserved);
        Assert.True(firstObserved.Year >= 2024);
        Assert.True(lastObserved.Year >= 2024);
    }

    [Fact]
    public void Format_IncludesMitreTechniquesInNoteContent()
    {
        var result = ResultWith(new Finding
        {
            Category = "C2Channel",
            Severity = Severity.High,
            SourceHost = "192.168.1.50",
            Target = "203.0.113.10:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddHours(1),
            ShortDescription = "Potential C2 channel detected",
            Details = "Periodic communication pattern",
            MitreTechniques =
            [
                new MitreTechnique { TechniqueId = "T1071.001", TechniqueName = "Web Protocols", Tactic = "Command and Control", WhyItMatters = "C2." }
            ]
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var notes = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "note")
            .ToList();

        Assert.Contains(notes, n => n.GetProperty("content").GetString()!.Contains("MITRE ATT&CK: T1071.001"));
    }

    [Fact]
    public void Format_IncludesConfidenceAndEvidenceSignals()
    {
        var result = ResultWith(new Finding
        {
            Category = "Beaconing",
            Severity = Severity.Critical,
            Confidence = DetectionConfidence.Confirmed,
            SourceHost = "192.168.1.10",
            Target = "10.0.0.5:443",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddHours(1),
            ShortDescription = "Beaconing detected",
            Details = "Periodic outbound traffic",
            EvidenceSignals =
            [
                new EvidenceSignal { Name = "Periodic outbound traffic", Source = EvidenceSignal.BehaviorSource, Explanation = "60s intervals" },
                new EvidenceSignal { Name = "Known malicious IP", Source = EvidenceSignal.ThreatIntelSource, Explanation = "Matched IOC" }
            ]
        });

        var stix = _formatter.Format(result, "");
        var doc = JsonDocument.Parse(stix);

        var notes = doc.RootElement.GetProperty("objects")
            .EnumerateArray()
            .Where(o => o.TryGetProperty("type", out var t) && t.GetString() == "note")
            .ToList();

        var note = Assert.Single(notes);
        var content = note.GetProperty("content").GetString()!;
        Assert.Contains("Confidence: Confirmed", content);
        Assert.Contains("Evidence Signals: Periodic outbound traffic; Known malicious IP", content);
    }
}
