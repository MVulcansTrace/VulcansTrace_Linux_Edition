using System.Globalization;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Core.Compliance;

/// <summary>
/// Resolves CIS control IDs to their control families.
/// </summary>
public static partial class CisFamilyResolver
{
    /// <summary>
    /// Maps CIS family numbers to human-readable names (CIS Ubuntu 24.04 LTS chapters).
    /// </summary>
    private static readonly Dictionary<string, string> FamilyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["1"] = "Initial Setup",
        ["2"] = "Services",
        ["3"] = "Network Configuration",
        ["4"] = "Logging and Auditing",
        ["5"] = "Access, Authentication and Authorization",
        ["6"] = "System Maintenance",
        ["7"] = "Optional Services",
    };

    /// <summary>
    /// Extracts the family identifier from a CIS control ID such as "CIS 4.5" or "CIS 10.1".
    /// Returns null if the ID does not match the expected pattern.
    /// </summary>
    public static string? ExtractFamilyId(string controlId)
    {
        if (string.IsNullOrWhiteSpace(controlId))
            return null;

        var match = ControlIdRegex().Match(controlId.Trim());
        if (match.Success)
        {
            return match.Groups[1].Value;
        }

        return null;
    }

    /// <summary>
    /// Gets the human-readable family name for a given family identifier.
    /// Returns "Other" if the family is not recognized.
    /// </summary>
    public static string GetFamilyName(string familyId)
    {
        if (FamilyNames.TryGetValue(familyId, out var name))
            return name;

        return "Other";
    }

    /// <summary>
    /// Resolves a CIS control ID to its full family name in one call.
    /// Returns null if the control ID cannot be parsed.
    /// </summary>
    public static string? ResolveFamilyName(string controlId)
    {
        var familyId = ExtractFamilyId(controlId);
        return familyId == null ? null : GetFamilyName(familyId);
    }

    [GeneratedRegex(@"^CIS\s+(\d+)(?:\.\d+)?", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex ControlIdRegex();
}
