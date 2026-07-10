using System.Globalization;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Core.Compliance;

/// <summary>
/// Resolves CIS control IDs to their control families.
/// </summary>
public static partial class CisFamilyResolver
{
    /// <summary>
    /// Maps the leading integer of a CIS control ID (the <c>CIS N.M</c> CIS Controls v8
    /// layer) to the CIS Controls v8 control name. Family grouping is keyed on that
    /// leading integer, so the labels follow the v8 control set (1–18).
    /// </summary>
    private static readonly Dictionary<string, string> FamilyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["1"] = "Inventory and Control of Enterprise Assets",
        ["2"] = "Inventory and Control of Software Assets",
        ["3"] = "Data Protection",
        ["4"] = "Secure Configuration of Enterprise Assets and Software",
        ["5"] = "Account Management",
        ["6"] = "Access Control Management",
        ["7"] = "Continuous Vulnerability Management",
        ["8"] = "Audit Log Management",
        ["9"] = "Email and Web Browser Protections",
        ["10"] = "Malware Defenses",
        ["11"] = "Data Recovery",
        ["12"] = "Network Infrastructure Management",
        ["13"] = "Network Monitoring and Defense",
        ["14"] = "Security Awareness and Skills Training",
        ["15"] = "Service Provider Management",
        ["16"] = "Application Software Security",
        ["17"] = "Incident Response Management",
        ["18"] = "Penetration Testing",
    };

    /// <summary>
    /// Extracts the family identifier from a numeric CIS control ID such as "CIS 4.5" or "CIS 10.1".
    /// Returns null when the entire value is not in numeric CIS identifier form.
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

    [GeneratedRegex(@"^CIS\s+(\d+)(?:\.\d+)*$", RegexOptions.IgnoreCase, "en-US")]
    private static partial Regex ControlIdRegex();
}
