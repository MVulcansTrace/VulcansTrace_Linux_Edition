using System.Text.Json;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Detects supported threat intelligence JSON formats from parsed document structure.
/// </summary>
public static class ThreatIntelFormatDetector
{
    /// <summary>
    /// Attempts to detect whether a JSON document is STIX or MISP.
    /// </summary>
    /// <param name="json">The raw JSON document.</param>
    /// <param name="format">The detected format.</param>
    /// <returns>True when the format is recognized.</returns>
    public static bool TryDetect(string json, out ThreatIntelBundleFormat format)
    {
        ArgumentNullException.ThrowIfNull(json);

        format = default;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            if (LooksLikeStix(root))
            {
                format = ThreatIntelBundleFormat.Stix;
                return true;
            }

            if (LooksLikeMisp(root))
            {
                format = ThreatIntelBundleFormat.Misp;
                return true;
            }

            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool LooksLikeStix(JsonElement root)
    {
        var hasObjectsArray = root.TryGetProperty("objects", out var objectsProp)
            && objectsProp.ValueKind == JsonValueKind.Array;
        if (!hasObjectsArray)
            return false;

        if (root.TryGetProperty("type", out var typeProp)
            && typeProp.ValueKind == JsonValueKind.String
            && string.Equals(typeProp.GetString(), "bundle", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return root.TryGetProperty("spec_version", out var specVersionProp)
            && specVersionProp.ValueKind == JsonValueKind.String
            && (specVersionProp.GetString()?.StartsWith("2.", StringComparison.Ordinal) == true);
    }

    private static bool LooksLikeMisp(JsonElement root)
    {
        if (root.TryGetProperty("Event", out var eventProp) && eventProp.ValueKind == JsonValueKind.Object)
            return HasMispCollections(eventProp);

        return HasMispCollections(root);
    }

    private static bool HasMispCollections(JsonElement element)
    {
        return (element.TryGetProperty("Attribute", out var attributesProp) && attributesProp.ValueKind == JsonValueKind.Array)
            || (element.TryGetProperty("Object", out var objectsProp) && objectsProp.ValueKind == JsonValueKind.Array);
    }
}
