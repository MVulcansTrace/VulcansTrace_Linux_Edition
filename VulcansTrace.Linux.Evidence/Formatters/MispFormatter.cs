using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formatter for exporting findings as a MISP event JSON that can be consumed by MISP
/// instances or re-imported by the VulcansTrace MISP parser.
/// </summary>
public sealed class MispFormatter : IEvidenceFormatter
{
    public string FileExtension => ".json";

    public string ContentType => "application/json";

    public string Format(AnalysisResult result, string originalLog)
        => Format(result, originalLog, DateTime.UtcNow);

    public string Format(AnalysisResult result, string originalLog, DateTime exportTimestampUtc)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var attributes = new List<MispAttribute>();

        foreach (var finding in result.Findings)
        {
            var comment = BuildComment(finding);
            var tags = BuildTags(finding);
            var addedForFinding = false;

            if (IsValidIpAddress(finding.SourceHost))
            {
                attributes.Add(BuildAttribute("ip-src", finding.SourceHost, comment, tags));
                addedForFinding = true;
            }

            var targetIp = ExtractTargetIp(finding.Target);
            if (!string.IsNullOrWhiteSpace(targetIp))
            {
                attributes.Add(BuildAttribute("ip-dst", targetIp, comment, tags));
                addedForFinding = true;
            }

            var targetPort = ExtractTargetPort(finding.Target);
            if (!string.IsNullOrWhiteSpace(targetPort) && IsValidPort(targetPort))
            {
                attributes.Add(BuildAttribute("port", targetPort, comment, tags));
                addedForFinding = true;
            }

            if (!addedForFinding)
            {
                // Ensure findings with no extractable IP/port are not silently dropped. This only
                // fires when nothing was added for this finding, so an IP-bearing finding never
                // also gets a redundant text attribute.
                var value = string.IsNullOrWhiteSpace(finding.ShortDescription)
                    ? $"{finding.Category} finding"
                    : finding.ShortDescription;
                attributes.Add(BuildAttribute("text", value, comment, tags));
            }
        }

        var mispEvent = new MispEvent
        {
            Info = "VulcansTrace analysis export",
            ThreatLevelId = SeverityToThreatLevel(result.Findings),
            // MISP stores event timestamps as unix-epoch seconds, not ISO-8601 strings.
            Timestamp = new DateTimeOffset(exportTimestampUtc).ToUnixTimeSeconds(),
            // Required/expected by external MISP instances on direct import. distribution "0" keeps
            // the event organisation-only; analysis "0" marks it as the initial export.
            Distribution = "0",
            Analysis = "0",
            Date = exportTimestampUtc.ToString("yyyy-MM-dd"),
            Attribute = attributes
        };

        var root = new MispEventRoot { Event = mispEvent };
        return JsonSerializer.Serialize(root, jsonOptions);
    }

    private static string BuildComment(Finding finding)
    {
        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(finding.RuleId))
            parts.Add($"Rule ID: {finding.RuleId}");

        parts.Add($"Category: {finding.Category}");
        parts.Add($"Severity: {finding.Severity}");

        if (!string.IsNullOrWhiteSpace(finding.Details))
            parts.Add($"Details: {finding.Details}");

        return string.Join(" | ", parts);
    }

    private static List<MispTag> BuildTags(Finding finding)
    {
        var tags = new List<MispTag>
        {
            new() { Name = $"category:{finding.Category}" },
            new() { Name = $"severity:{finding.Severity}" }
        };

        foreach (var technique in finding.MitreTechniques)
        {
            if (!string.IsNullOrWhiteSpace(technique.TechniqueId))
                tags.Add(new MispTag { Name = $"mitre-attack:{technique.TechniqueId}" });
        }

        return tags;
    }

    private static MispAttribute BuildAttribute(string type, string value, string comment, List<MispTag> tags) => new()
    {
        Type = type,
        Value = value,
        Comment = comment,
        Tag = tags,
        Category = CategoryForType(type),
        ToIds = ShouldBlock(type)
    };

    private static string CategoryForType(string type) => type switch
    {
        "ip-src" or "ip-dst" or "port" => "Network activity",
        _ => "Other"
    };

    // Only source/destination IPs are strong enough indicators to flag for IDS blocking; a bare
    // port or a free-text finding is not actionable on its own.
    private static bool ShouldBlock(string type) => type is "ip-src" or "ip-dst";

    private static string SeverityToThreatLevel(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
            return "4"; // MISP threat_level_id 4 = undefined.

        // severityOrder is most-severe-first, so the most severe finding has the smallest index.
        // The event threat level must reflect the MOST severe finding present, so take the Min
        // (Max would instead report the least severe finding, e.g. Critical+Info -> "Low").
        var severityOrder = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info };
        var mostSevereIndex = findings.Min(f => Array.IndexOf(severityOrder, f.Severity));
        return mostSevereIndex switch
        {
            0 or 1 => "1", // Critical or High
            2 => "2",      // Medium
            _ => "3"       // Low or Info
        };
    }

    private static bool IsValidIpAddress(string? ipString)
        => !string.IsNullOrWhiteSpace(ipString) && IPAddress.TryParse(ipString, out _);

    private static bool IsValidPort(string value)
        => int.TryParse(value, out var port) && port is >= 1 and <= 65535;

    private static string? ExtractTargetIp(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
            return null;

        // Handle bracketed IPv6 with port (e.g. "[2001:db8::1]:443")
        if (target.StartsWith('['))
        {
            var bracketEnd = target.IndexOf(']');
            if (bracketEnd > 1)
            {
                var candidate = target.Substring(1, bracketEnd - 1);
                if (IPAddress.TryParse(candidate, out _))
                    return candidate;
            }
        }

        // Handle "IP:port" — the last colon separates the port number.
        var lastColon = target.LastIndexOf(':');
        if (lastColon > 0)
        {
            var candidate = target[..lastColon];
            if (IPAddress.TryParse(candidate, out _))
                return candidate;
        }

        if (IPAddress.TryParse(target, out _))
            return target;

        return null;
    }

    private static string? ExtractTargetPort(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
            return null;

        // Handle bracketed IPv6 with port (e.g. "[2001:db8::1]:443")
        if (target.StartsWith('['))
        {
            var bracketEnd = target.IndexOf(']');
            if (bracketEnd > 0 && bracketEnd + 1 < target.Length && target[bracketEnd + 1] == ':')
                return target[(bracketEnd + 2)..];
        }

        // For IPv4 "IP:port" the last colon separates the port.
        var lastColon = target.LastIndexOf(':');
        if (lastColon > 0 && !target[..lastColon].Contains(':'))
            return target[(lastColon + 1)..];

        return null;
    }
}

internal sealed class MispEventRoot
{
    [JsonPropertyName("Event")]
    public MispEvent Event { get; set; } = new();
}

internal sealed class MispEvent
{
    [JsonPropertyName("info")]
    public string Info { get; set; } = string.Empty;

    [JsonPropertyName("threat_level_id")]
    public string ThreatLevelId { get; set; } = "3";

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("distribution")]
    public string Distribution { get; set; } = "0";

    [JsonPropertyName("analysis")]
    public string Analysis { get; set; } = "0";

    [JsonPropertyName("date")]
    public string Date { get; set; } = string.Empty;

    [JsonPropertyName("Attribute")]
    public List<MispAttribute> Attribute { get; set; } = new();
}

internal sealed class MispAttribute
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("category")]
    public string Category { get; set; } = "Other";

    [JsonPropertyName("to_ids")]
    public bool ToIds { get; set; }

    [JsonPropertyName("comment")]
    public string? Comment { get; set; }

    [JsonPropertyName("Tag")]
    public List<MispTag>? Tag { get; set; }
}

internal sealed class MispTag
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}
