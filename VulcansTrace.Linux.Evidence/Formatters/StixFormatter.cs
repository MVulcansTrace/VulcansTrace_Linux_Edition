using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Formatter for exporting findings in STIX 2.1 format compatible with threat intelligence platforms.
/// </summary>
public sealed class StixFormatter : IEvidenceFormatter
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

        var bundle = new StixBundle
        {
            Id = StableStixId("bundle", BuildBundleSeed(result, originalLog, exportTimestampUtc)),
            Objects = new List<object>()
        };

        var now = NormalizeTime(exportTimestampUtc, DateTime.UtcNow);
        var identity = new StixIdentity
        {
            Id = StableStixId("identity", "VulcansTrace Linux Edition"),
            Created = now,
            Modified = now,
            Name = "VulcansTrace Linux Edition",
            IdentityClass = "organization"
        };
        bundle.Objects.Add(identity);

        var ipObjects = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string EnsureIpObject(string ip)
        {
            if (!ipObjects.TryGetValue(ip, out var id))
            {
                var isV6 = ip.Contains(':');
                id = StableStixId(isV6 ? "ipv6-addr" : "ipv4-addr", ip);
                ipObjects[ip] = id;

                if (isV6)
                {
                    bundle.Objects.Add(new StixIpv6Address
                    {
                        Id = id,
                        Value = ip
                    });
                }
                else
                {
                    bundle.Objects.Add(new StixIpv4Address
                    {
                        Id = id,
                        Value = ip
                    });
                }
            }

            return id;
        }

        foreach (var item in result.Findings.Select((Finding, Index) => new { Finding, Index }))
        {
            var finding = item.Finding;
            var objectRefs = new List<string>();

            if (IsValidIpAddress(finding.SourceHost))
            {
                objectRefs.Add(EnsureIpObject(finding.SourceHost));
            }

            var targetIp = ExtractTargetIp(finding.Target);
            if (!string.IsNullOrWhiteSpace(targetIp) && IsValidIpAddress(targetIp))
            {
                objectRefs.Add(EnsureIpObject(targetIp));
            }

            if (objectRefs.Count == 0)
            {
                // Emit a standalone note for non-IP findings (e.g., KernelModule)
                // so they are not silently dropped from the STIX export.
                var standaloneNote = new StixNote
                {
                    Id = StableStixId("note", finding.Id.ToString(), item.Index.ToString(), BuildNoteContent(finding)),
                    Created = now,
                    Modified = now,
                    Content = BuildNoteContent(finding),
                    Labels = new[] { finding.Category }
                };
                bundle.Objects.Add(standaloneNote);
                continue;
            }

            var firstObserved = NormalizeTime(finding.TimeRangeStart, now);
            var lastObserved = NormalizeTime(finding.TimeRangeEnd, firstObserved);

            var observed = new StixObservedData
            {
                Id = StableStixId("observed-data", finding.Id.ToString(), item.Index.ToString(), string.Join("|", objectRefs)),
                Created = now,
                Modified = now,
                FirstObserved = firstObserved,
                LastObserved = lastObserved,
                NumberObserved = 1,
                ObjectRefs = objectRefs,
                Labels = new[] { finding.Category }
            };
            bundle.Objects.Add(observed);

            var note = new StixNote
            {
                Id = StableStixId("note", finding.Id.ToString(), item.Index.ToString(), BuildNoteContent(finding)),
                Created = now,
                Modified = now,
                Content = BuildNoteContent(finding),
                ObjectRefs = new List<string> { observed.Id }
            };
            bundle.Objects.Add(note);
        }

        if (result.Findings.Any(f => f.Category.Equals("C2Channel", StringComparison.OrdinalIgnoreCase)))
        {
            var malware = new StixMalware
            {
                Id = StableStixId("malware", "Potential Malware C2 Activity"),
                Created = now,
                Modified = now,
                Name = "Potential Malware C2 Activity",
                IsFamily = false,
                Description = "Detected potential command-and-control channel behavior"
            };
            bundle.Objects.Add(malware);
        }

        return JsonSerializer.Serialize(bundle, jsonOptions);
    }

    private static string BuildBundleSeed(AnalysisResult result, string originalLog, DateTime exportTimestampUtc)
    {
        var findingSeed = string.Join("|", result.Findings.Select(f =>
            $"{f.Id}:{f.Category}:{f.Severity}:{f.SourceHost}:{f.Target}:{f.TimeRangeStart:O}:{f.TimeRangeEnd:O}:{f.ShortDescription}:{f.Details}"));
        var logHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(originalLog ?? string.Empty))).ToLowerInvariant();
        return $"{exportTimestampUtc:O}|{result.TotalLines}|{result.ParsedLines}|{result.SkippedLineCount}|{findingSeed}|{logHash}";
    }

    private static string StableStixId(string type, params string[] parts)
    {
        var seed = $"{type}:{string.Join('\u001f', parts)}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var bytes = hash[..16];

        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        return $"{type}--{new Guid(bytes, bigEndian: true):D}";
    }

    private static string? ExtractTargetIp(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        // Handle bracketed IPv6 with port (e.g. "[2001:db8::1]:443")
        if (target.StartsWith('['))
        {
            var bracketEnd = target.IndexOf(']');
            if (bracketEnd > 1)
            {
                var candidate = target.Substring(1, bracketEnd - 1);
                if (IPAddress.TryParse(candidate, out _))
                {
                    return candidate;
                }
            }
        }

        // Handle "IP:port" — the last colon separates the port number.
        // For IPv6 (e.g. "2001:db8::1:443") we want "2001:db8::1",
        // for IPv4 (e.g. "10.0.0.1:22") we want "10.0.0.1".
        var lastColon = target.LastIndexOf(':');
        if (lastColon > 0)
        {
            var candidate = target[..lastColon];
            if (IPAddress.TryParse(candidate, out _))
            {
                return candidate;
            }
        }

        // Try the whole string (no port suffix)
        if (IPAddress.TryParse(target, out _))
        {
            return target;
        }

        return null;
    }

    private static bool IsValidIpAddress(string ipString)
    {
        return IPAddress.TryParse(ipString, out _);
    }

    private static DateTime NormalizeTime(DateTime value, DateTime fallback)
    {
        if (value == DateTime.MinValue)
        {
            return fallback;
        }

        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
    }

    private static string BuildNoteContent(Finding finding)
    {
        var ruleId = string.IsNullOrWhiteSpace(finding.RuleId)
            ? string.Empty
            : $"Rule ID: {finding.RuleId}\n";

        var cis = finding.CisMappings.Count > 0
            ? "CIS Mapping: " + string.Join("; ", finding.CisMappings.Select(m => $"{m.ControlId} ({m.ControlName})")) + "\n"
            : string.Empty;

        return ruleId +
               cis +
               $"Category: {finding.Category}\n" +
               $"Severity: {finding.Severity}\n" +
               $"Source: {finding.SourceHost}\n" +
               $"Target: {finding.Target}\n" +
               $"Summary: {finding.ShortDescription}\n" +
               $"Details: {finding.Details}";
    }
}

// STIX 2.1 Object Models
public sealed class StixBundle
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "bundle";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("spec_version")]
    public string SpecVersion { get; set; } = "2.1";

    [JsonPropertyName("objects")]
    public List<object> Objects { get; set; } = new();
}

public sealed class StixIdentity
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "identity";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

    [JsonPropertyName("modified")]
    public DateTime Modified { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("identity_class")]
    public string IdentityClass { get; set; } = string.Empty;
}

public sealed class StixObservedData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "observed-data";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

    [JsonPropertyName("modified")]
    public DateTime Modified { get; set; }

    [JsonPropertyName("first_observed")]
    public DateTime FirstObserved { get; set; }

    [JsonPropertyName("last_observed")]
    public DateTime LastObserved { get; set; }

    [JsonPropertyName("number_observed")]
    public int NumberObserved { get; set; } = 1;

    [JsonPropertyName("object_refs")]
    public List<string>? ObjectRefs { get; set; }

    [JsonPropertyName("labels")]
    public string[]? Labels { get; set; }
}

public sealed class StixNote
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "note";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

    [JsonPropertyName("modified")]
    public DateTime Modified { get; set; }

    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;

    [JsonPropertyName("object_refs")]
    public List<string>? ObjectRefs { get; set; }

    [JsonPropertyName("labels")]
    public string[]? Labels { get; set; }
}

public sealed class StixIpv4Address
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "ipv4-addr";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

public sealed class StixIpv6Address
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "ipv6-addr";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;
}

public sealed class StixMalware
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "malware";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("created")]
    public DateTime Created { get; set; }

    [JsonPropertyName("modified")]
    public DateTime Modified { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("is_family")]
    public bool IsFamily { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
