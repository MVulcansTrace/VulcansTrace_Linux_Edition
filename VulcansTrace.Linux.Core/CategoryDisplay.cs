using System.Text;

namespace VulcansTrace.Linux.Core;

/// <summary>
/// Turns internal category tokens (PascalCase / camelCase, plus a few acronyms)
/// into human-readable labels for display. The raw category value is preserved
/// everywhere else (grouping, filtering, persistence, tests); this is display-only.
/// </summary>
public static class CategoryDisplay
{
    /// <summary>
    /// Whole-token overrides for values that do not split cleanly into words.
    /// Keyed case-insensitively on the raw token.
    /// </summary>
    private static readonly Dictionary<string, string> Overrides = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SSH"] = "SSH",
        ["Mac"] = "MAC",
        ["Yara"] = "YARA"
    };

    /// <summary>
    /// Returns a spaced, human-readable form of a category token.
    /// Examples: "FilesystemAudit" -&gt; "Filesystem Audit",
    /// "C2Channel" -&gt; "C2 Channel", "Yara" -&gt; "YARA", "Firewall" -&gt; "Firewall".
    /// Null/whitespace returns <see cref="string.Empty"/>.
    /// </summary>
    public static string ToDisplayName(string? category)
    {
        if (string.IsNullOrWhiteSpace(category))
            return string.Empty;

        var token = category.Trim();

        if (Overrides.TryGetValue(token, out var label))
            return label;

        return SplitPascalCase(token);
    }

    private static string SplitPascalCase(string value)
    {
        var sb = new StringBuilder(value.Length + 4);

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if (i > 0 && char.IsUpper(c))
            {
                char prev = value[i - 1];
                bool nextIsLower = i + 1 < value.Length && char.IsLower(value[i + 1]);

                // Start a new word when the previous char is lower/digit,
                // or when we are at the last char of an acronym run (prev upper, next lower).
                if (char.IsLower(prev) || char.IsDigit(prev) || (char.IsUpper(prev) && nextIsLower))
                    sb.Append(' ');
            }

            sb.Append(c);
        }

        return sb.ToString();
    }
}
