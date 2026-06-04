using System.Text.Json;
using System.Text.RegularExpressions;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Parses STIX 2.1 bundle JSON into IOC entries.
/// </summary>
public static class StixParser
{
    private static readonly Regex PatternComparisonRegex = new(
        @"([\w\-]+):([\w\-_]+(?:\.'[^']+')?)\s*=\s*('[^']*'|[^\s\]\)]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Parses a STIX 2.1 bundle JSON string.
    /// </summary>
    /// <param name="json">The raw STIX bundle JSON.</param>
    /// <returns>An import result containing extracted IOCs and any warnings.</returns>
    public static ThreatIntelImportResult Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        var entries = new List<IocEntry>();
        var warnings = new List<string>();
        int skipped = 0;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                warnings.Add("STIX root is not an object.");
                return new ThreatIntelImportResult { SkippedCount = 0, Warnings = warnings };
            }

            if (!root.TryGetProperty("objects", out var objectsProp) || objectsProp.ValueKind != JsonValueKind.Array)
            {
                warnings.Add("STIX bundle missing 'objects' array.");
                return new ThreatIntelImportResult { SkippedCount = 0, Warnings = warnings };
            }

            foreach (var obj in objectsProp.EnumerateArray())
            {
                if (obj.ValueKind != JsonValueKind.Object)
                    continue;

                if (!obj.TryGetProperty("type", out var typeProp))
                    continue;

                var type = typeProp.GetString() ?? string.Empty;
                int confidence = ExtractConfidence(obj);

                switch (type)
                {
                    case "ipv4-addr":
                        if (obj.TryGetProperty("value", out var ipv4Value) && ipv4Value.ValueKind == JsonValueKind.String)
                        {
                            entries.Add(CreateEntry(IocType.IPv4, ipv4Value.GetString()!, confidence, obj));
                        }
                        break;

                    case "ipv6-addr":
                        if (obj.TryGetProperty("value", out var ipv6Value) && ipv6Value.ValueKind == JsonValueKind.String)
                        {
                            entries.Add(CreateEntry(IocType.IPv6, ipv6Value.GetString()!, confidence, obj));
                        }
                        break;

                    case "domain-name":
                        if (obj.TryGetProperty("value", out var domainValue) && domainValue.ValueKind == JsonValueKind.String)
                        {
                            entries.Add(CreateEntry(IocType.Domain, domainValue.GetString()!, confidence, obj));
                        }
                        break;

                    case "url":
                        if (obj.TryGetProperty("value", out var urlValue) && urlValue.ValueKind == JsonValueKind.String)
                        {
                            entries.Add(CreateEntry(IocType.URL, urlValue.GetString()!, confidence, obj));
                        }
                        break;

                    case "file":
                        ExtractFileHashes(obj, entries, confidence);
                        break;

                    case "indicator":
                        if (obj.TryGetProperty("pattern", out var patternProp) && patternProp.ValueKind == JsonValueKind.String)
                        {
                            var pattern = patternProp.GetString() ?? string.Empty;
                            var parsed = ParsePattern(pattern, confidence, obj);
                            entries.AddRange(parsed.Entries);
                            warnings.AddRange(parsed.Warnings);
                            skipped += parsed.Skipped;
                        }
                        break;

                    default:
                        // Skip unknown object types silently
                        break;
                }
            }
        }
        catch (JsonException ex)
        {
            warnings.Add($"STIX JSON parse error: {ex.Message}");
        }

        return new ThreatIntelImportResult
        {
            Entries = entries,
            SkippedCount = skipped,
            Warnings = warnings
        };
    }

    private static IocEntry CreateEntry(IocType type, string value, int confidence, JsonElement obj)
    {
        string? description = null;
        if (obj.TryGetProperty("description", out var descProp) && descProp.ValueKind == JsonValueKind.String)
        {
            description = descProp.GetString();
        }

        if (obj.TryGetProperty("labels", out var labelsProp) && labelsProp.ValueKind == JsonValueKind.Array)
        {
            var labels = string.Join(", ", labelsProp.EnumerateArray().Select(l => l.GetString()).Where(s => !string.IsNullOrEmpty(s)));
            if (!string.IsNullOrEmpty(labels))
            {
                description = string.IsNullOrEmpty(description) ? labels : $"{description} | Labels: {labels}";
            }
        }

        return new IocEntry
        {
            Type = type,
            Value = value,
            Confidence = confidence,
            Source = "STIX",
            Description = description,
            ImportedAt = DateTime.UtcNow
        };
    }

    private static int ExtractConfidence(JsonElement obj)
    {
        if (obj.TryGetProperty("confidence", out var confProp))
        {
            if (confProp.ValueKind == JsonValueKind.Number && confProp.TryGetInt32(out var conf))
            {
                return Math.Clamp(conf, 0, 100);
            }
        }
        return 50;
    }

    private static void ExtractFileHashes(JsonElement fileObj, List<IocEntry> entries, int confidence)
    {
        if (!fileObj.TryGetProperty("hashes", out var hashesProp) || hashesProp.ValueKind != JsonValueKind.Object)
            return;

        foreach (var hashProp in hashesProp.EnumerateObject())
        {
            var hashType = hashProp.Name.ToUpperInvariant();
            if (hashType is "SHA-256" or "SHA256")
            {
                var hashValue = hashProp.Value.GetString();
                if (!string.IsNullOrWhiteSpace(hashValue))
                {
                    entries.Add(CreateEntry(IocType.FileHash, hashValue.ToLowerInvariant(), confidence, fileObj));
                }
            }
        }
    }

    private static (List<IocEntry> Entries, List<string> Warnings, int Skipped) ParsePattern(string pattern, int confidence, JsonElement obj)
    {
        var entries = new List<IocEntry>();
        var warnings = new List<string>();
        int skipped = 0;

        var matches = PatternComparisonRegex.Matches(pattern);
        if (matches.Count == 0)
        {
            skipped++;
            warnings.Add($"Skipped unparseable STIX indicator pattern: {pattern.Truncate(200)}");
            return (entries, warnings, skipped);
        }

        foreach (Match match in matches)
        {
            var objType = match.Groups[1].Value;
            var property = match.Groups[2].Value.Replace("'", "");
            var value = match.Groups[3].Value.Trim('\'');

            var entry = (objType, property) switch
            {
                ("ipv4-addr", "value") => CreateEntry(IocType.IPv4, value, confidence, obj),
                ("ipv6-addr", "value") => CreateEntry(IocType.IPv6, value, confidence, obj),
                ("domain-name", "value") => CreateEntry(IocType.Domain, value, confidence, obj),
                ("url", "value") => CreateEntry(IocType.URL, value, confidence, obj),
                ("network-traffic", "dst_port") when int.TryParse(value, out _) => CreateEntry(IocType.Port, value, confidence, obj),
                ("network-traffic", "src_port") when int.TryParse(value, out _) => CreateEntry(IocType.Port, value, confidence, obj),
                ("file", var p) when p.Contains("SHA-256") || p.Contains("SHA256") => CreateEntry(IocType.FileHash, value.ToLowerInvariant(), confidence, obj),
                _ => null
            };

            if (entry != null)
            {
                entries.Add(entry);
            }
            else
            {
                skipped++;
            }
        }

        return (entries, warnings, skipped);
    }

    private static string Truncate(this string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            return value ?? string.Empty;
        return value[..maxLength] + "...";
    }
}
