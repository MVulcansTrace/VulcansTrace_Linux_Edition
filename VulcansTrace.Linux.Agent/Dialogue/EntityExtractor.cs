using System.Text.RegularExpressions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Extracts structured entities from raw user queries: rule IDs, session IDs,
/// ordinals, category keywords, and anaphoric references.
/// </summary>
public sealed class EntityExtractor
{
    private static readonly Regex RuleIdPattern = new(@"[A-Za-z]{2,}-\d{3,}", RegexOptions.Compiled);
    private static readonly Regex SessionIdPattern = new(@"\b[0-9a-fA-F]{8}\b", RegexOptions.Compiled);

    private static readonly Regex OrdinalWordPattern = new(
        @"\b(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex OrdinalNumberPattern = new(
        @"\b(\d+)(?:st|nd|rd|th)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex NumberPattern = new(@"\b(\d+)\b", RegexOptions.Compiled);

    private static readonly HashSet<string> AnaphoraWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "it", "that", "this", "those", "these", "them", "one", "ones",
        "the one", "the ones", "this one", "that one", "above", "previous"
    };

    private static readonly string[] CategoryKeywords =
    {
        // Specific keywords must come before generic substrings they contain.
        "firewall", "iptables", "nftables",
        "ssh", "sshd",
        "filesystem", "suid", "sgid", "world-writable", "sticky", "unowned",
        "packagevulnerability", "cve",
        "threatintel", "threat-intel",
        "processruntime", "ld_preload", "deleted binary",
        "useraccount",

        // Generic keywords.
        "network", "route", "interface", "connection",
        "service", "daemon", "systemctl",
        "port", "listening",
        "file", "filepermission", "permissions",
        "kernel", "sysctl",
        "user", "account", "password", "shadow", "uid", "pam",
        "logging", "rsyslog", "journald", "logrotate", "forwarding", "syslog",
        "cron", "crontab", "scheduled",
        "package",
        "container", "docker",
        "kubernetes", "k8s", "pod",
        "ioc", "indicator",
        "yara", "malware",
        "process", "runtime", "proc", "injection"
    };

    /// <summary>Extracts the first rule ID found in the query, or null.</summary>
    public string? ExtractRuleId(string query)
    {
        var match = RuleIdPattern.Match(query);
        return match.Success ? match.Value : null;
    }

    /// <summary>Extracts the first session ID found in the query, or null.</summary>
    public string? ExtractSessionId(string query)
    {
        var match = SessionIdPattern.Match(query);
        return match.Success ? match.Value : null;
    }

    /// <summary>
    /// Extracts an ordinal reference (e.g., "third one", "3rd", "number 3")
    /// as a 1-based index, or null if none is found.
    /// </summary>
    public int? ExtractOrdinal(string query)
    {
        var normalized = query.ToLowerInvariant();

        var wordMatch = OrdinalWordPattern.Match(normalized);
        if (wordMatch.Success)
            return WordToOrdinal(wordMatch.Value);

        var numMatch = OrdinalNumberPattern.Match(normalized);
        if (numMatch.Success && int.TryParse(numMatch.Groups[1].Value, out var ordinal))
            return ordinal;

        // "number 3" or "the 3rd" already handled; try bare "3" only near context words.
        if (normalized.Contains("one") || normalized.Contains("ones") || normalized.Contains("finding"))
        {
            var bareMatch = NumberPattern.Match(normalized);
            if (bareMatch.Success && int.TryParse(bareMatch.Groups[1].Value, out var bare))
                return bare;
        }

        return null;
    }

    /// <summary>Extracts the first matching category keyword, or null.</summary>
    public string? ExtractCategory(string query)
    {
        var normalized = query.ToLowerInvariant();
        foreach (var keyword in CategoryKeywords)
        {
            if (normalized.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return keyword;
        }

        return null;
    }

    /// <summary>Determines whether the query contains an anaphoric reference.</summary>
    public bool HasAnaphora(string query)
    {
        var normalized = query.ToLowerInvariant();
        foreach (var word in AnaphoraWords)
        {
            if (IsWholeWordOrPhrase(normalized, word))
                return true;
        }

        return false;
    }

    private static bool IsWholeWordOrPhrase(string normalized, string word)
    {
        // For multi-word phrases, require exact substring match.
        if (word.Contains(' '))
            return normalized.Contains(word, StringComparison.OrdinalIgnoreCase);

        // For single-word anaphora, scan all occurrences and require word boundaries.
        var startIndex = 0;
        while (true)
        {
            var index = normalized.IndexOf(word, startIndex, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
                return false;

            var before = index == 0 || !char.IsLetterOrDigit(normalized[index - 1]);
            var after = index + word.Length >= normalized.Length || !char.IsLetterOrDigit(normalized[index + word.Length]);
            if (before && after)
                return true;

            startIndex = index + 1;
        }
    }

    /// <summary>
    /// Extracts an explicit target from the query if present.
    /// Priority: rule ID, session ID, category, ordinal.
    /// </summary>
    public ExtractedEntities ExtractAll(string query)
    {
        return new ExtractedEntities(
            ExtractRuleId(query),
            ExtractSessionId(query),
            ExtractCategory(query),
            ExtractOrdinal(query),
            HasAnaphora(query));
    }

    private static int WordToOrdinal(string word) => word.ToLowerInvariant() switch
    {
        "first" => 1,
        "second" => 2,
        "third" => 3,
        "fourth" => 4,
        "fifth" => 5,
        "sixth" => 6,
        "seventh" => 7,
        "eighth" => 8,
        "ninth" => 9,
        "tenth" => 10,
        _ => 0
    };
}

/// <summary>
/// Structured extraction result from a single user query.
/// </summary>
public sealed record ExtractedEntities(
    string? RuleId,
    string? SessionId,
    string? Category,
    int? Ordinal,
    bool HasAnaphora);
