using System.Text.Json;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Parses MISP event JSON into IOC entries.
/// </summary>
public static class MispParser
{
    /// <summary>
    /// Parses a MISP event JSON string.
    /// </summary>
    /// <param name="json">The raw MISP JSON.</param>
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
                warnings.Add("MISP root is not an object.");
                return new ThreatIntelImportResult { SkippedCount = 0, Warnings = warnings };
            }

            // MISP can be wrapped in Event or be the Event directly
            var eventElement = root;
            if (root.TryGetProperty("Event", out var eventProp) && eventProp.ValueKind == JsonValueKind.Object)
            {
                eventElement = eventProp;
            }

            var eventConfidence = ExtractEventConfidence(eventElement);

            // Parse top-level attributes
            if (eventElement.TryGetProperty("Attribute", out var attributesProp) && attributesProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var attr in attributesProp.EnumerateArray())
                {
                    var results = ParseAttribute(attr, eventConfidence);
                    foreach (var result in results)
                    {
                        if (result.Entry != null)
                        {
                            entries.Add(result.Entry);
                        }
                        else
                        {
                            skipped++;
                            if (result.Warning != null)
                                warnings.Add(result.Warning);
                        }
                    }
                }
            }

            // Parse objects and their attributes
            if (eventElement.TryGetProperty("Object", out var objectsProp) && objectsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var obj in objectsProp.EnumerateArray())
                {
                    if (obj.TryGetProperty("Attribute", out var objAttrsProp) && objAttrsProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var attr in objAttrsProp.EnumerateArray())
                        {
                            var results = ParseAttribute(attr, eventConfidence);
                            foreach (var result in results)
                            {
                                if (result.Entry != null)
                                {
                                    entries.Add(result.Entry);
                                }
                                else
                                {
                                    skipped++;
                                    if (result.Warning != null)
                                        warnings.Add(result.Warning);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            warnings.Add($"MISP JSON parse error: {ex.Message}");
        }

        return new ThreatIntelImportResult
        {
            Entries = entries,
            SkippedCount = skipped,
            Warnings = warnings
        };
    }

    private static List<(IocEntry? Entry, string? Warning)> ParseAttribute(JsonElement attr, int eventConfidence)
    {
        var results = new List<(IocEntry? Entry, string? Warning)>();

        if (attr.ValueKind != JsonValueKind.Object)
            return results;

        if (!attr.TryGetProperty("type", out var typeProp) || typeProp.ValueKind != JsonValueKind.String)
            return results;

        if (!attr.TryGetProperty("value", out var valueProp) || valueProp.ValueKind != JsonValueKind.String)
            return results;

        var mispType = typeProp.GetString() ?? string.Empty;
        var rawValue = valueProp.GetString() ?? string.Empty;
        var confidence = ExtractAttributeConfidence(attr, eventConfidence);

        string? description = null;
        if (attr.TryGetProperty("comment", out var commentProp) && commentProp.ValueKind == JsonValueKind.String)
        {
            description = commentProp.GetString();
        }

        if (attr.TryGetProperty("Tag", out var tagsProp) && tagsProp.ValueKind == JsonValueKind.Array)
        {
            var tags = string.Join(", ", tagsProp.EnumerateArray()
                .Select(t => t.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null)
                .Where(s => !string.IsNullOrEmpty(s)));
            if (!string.IsNullOrEmpty(tags))
            {
                description = string.IsNullOrEmpty(description) ? tags : $"{description} | Tags: {tags}";
            }
        }

        var lowerType = mispType.ToLowerInvariant();

        // Handle composite types that produce multiple IOCs
        if (lowerType is "ip-dst|port" or "ip-src|port")
        {
            var parts = rawValue.Split('|');
            if (parts.Length >= 2)
            {
                var ip = parts[0].Trim();
                var port = parts[1].Trim();
                if (!string.IsNullOrWhiteSpace(ip))
                {
                    results.Add((CreateEntry(TryParseIp(ip), ip, confidence, description), null));
                }
                if (!string.IsNullOrWhiteSpace(port) && int.TryParse(port, out _))
                {
                    results.Add((CreateEntry(IocType.Port, port, confidence, description), null));
                }
            }
            return results;
        }

        // Handle filename|hash composites
        var value = rawValue;
        string algorithm = string.Empty;
        if (value.Contains('|'))
        {
            var parts = value.Split('|');
            value = parts.Length > 1 ? parts[1] : parts[0];
            algorithm = lowerType switch
            {
                var t when t.Contains("md5") => "MD5",
                var t when t.Contains("sha1") => "SHA-1",
                var t when t.Contains("sha256") => "SHA-256",
                _ => string.Empty
            };
        }
        else
        {
            algorithm = lowerType switch
            {
                "md5" => "MD5",
                "sha1" => "SHA-1",
                "sha256" => "SHA-256",
                _ => string.Empty
            };
        }

        value = value.Trim();
        if (string.IsNullOrWhiteSpace(value))
            return results;

        var (iocType, normalizedValue) = lowerType switch
        {
            "ip-dst" or "ip-src" => (TryParseIp(value), value),
            "domain" or "domain|ip" or "hostname" => (IocType.Domain, value),
            "md5" or "sha1" or "sha256" or "filename|md5" or "filename|sha1" or "filename|sha256" => (IocType.FileHash, value.ToLowerInvariant()),
            "url" or "uri" => (IocType.URL, value),
            "port" => (int.TryParse(value, out _) ? IocType.Port : (IocType?)null, value),
            _ => ((IocType?)null, value)
        };

        if (iocType == null)
        {
            results.Add((null, $"Skipped unsupported MISP attribute type: {mispType}"));
            return results;
        }

        var entry = CreateEntry(iocType.Value, normalizedValue, confidence, description);
        if (!string.IsNullOrEmpty(algorithm))
        {
            entry = entry with { Algorithm = algorithm };
        }
        results.Add((entry, null));
        return results;
    }

    private static IocEntry CreateEntry(IocType type, string value, int confidence, string? description)
    {
        return new IocEntry
        {
            Type = type,
            Value = value,
            ThreatScore = confidence,
            Source = "MISP",
            Description = description,
            ImportedAt = DateTime.UtcNow
        };
    }

    private static IocType TryParseIp(string value)
    {
        if (value.Contains(':') && !value.Contains('.'))
            return IocType.IPv6;
        return IocType.IPv4;
    }

    private static int ExtractEventConfidence(JsonElement eventElement)
    {
        if (eventElement.TryGetProperty("threat_level_id", out var threatLevelProp))
        {
            if (threatLevelProp.ValueKind == JsonValueKind.String && int.TryParse(threatLevelProp.GetString(), out var tlStr))
            {
                return ThreatLevelToConfidence(tlStr);
            }
            if (threatLevelProp.ValueKind == JsonValueKind.Number && threatLevelProp.TryGetInt32(out var tlNum))
            {
                return ThreatLevelToConfidence(tlNum);
            }
        }
        return 50;
    }

    private static int ThreatLevelToConfidence(int threatLevelId)
    {
        // MISP threat_level_id: 1 = high, 2 = medium, 3 = low, 4 = very low/undefined
        return threatLevelId switch
        {
            1 => 80,
            2 => 60,
            3 => 40,
            4 => 20,
            _ => 50
        };
    }

    private static int ExtractAttributeConfidence(JsonElement attr, int eventConfidence)
    {
        if (attr.TryGetProperty("Tag", out var tagsProp) && tagsProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var tag in tagsProp.EnumerateArray())
            {
                var name = tag.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
                if (!string.IsNullOrEmpty(name) && name.StartsWith("confidence:", StringComparison.OrdinalIgnoreCase))
                {
                    var numPart = name["confidence:".Length..].Trim();
                    if (int.TryParse(numPart, out var conf))
                    {
                        return Math.Clamp(conf, 0, 100);
                    }
                }
            }
        }

        return eventConfidence;
    }
}
