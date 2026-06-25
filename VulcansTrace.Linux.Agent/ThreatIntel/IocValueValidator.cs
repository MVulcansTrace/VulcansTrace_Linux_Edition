using System.Globalization;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.ThreatIntel;

/// <summary>
/// Shared IOC value checks used by parsers and persistence validators.
/// </summary>
internal static partial class IocValueValidator
{
    public static bool IsValidPort(string value)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            && port is >= 1 and <= 65535;

    public static bool IsValidHash(string value)
        => HexRegex().IsMatch(value) || PrefixedHashRegex().IsMatch(value);

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexRegex();

    [GeneratedRegex("^(MD5|SHA-?1|SHA-?256|SHA-?512):[0-9a-fA-F]+$", RegexOptions.IgnoreCase)]
    private static partial Regex PrefixedHashRegex();
}
