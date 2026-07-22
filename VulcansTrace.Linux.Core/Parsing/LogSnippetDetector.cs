using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Core.Parsing;

/// <summary>
/// Deterministic heuristic for the unified hero input (UI v2 Phase 3): decides
/// whether the box content is a pasted log snippet (run analysis) or a chat
/// message (send to the agent). Same content must always give the same answer —
/// no hidden modes — so the rule is a fixed count of log-looking lines.
/// </summary>
public static class LogSnippetDetector
{
    /// <summary>Minimum number of log-looking lines before the intent flips to Analyze.</summary>
    public const int LogLineThreshold = 3;

    private static readonly Regex LogLineRegex = new(
        @"^\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\b" // syslog stamp
        + @"|^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}" // ISO stamp
        + @"|\b(?:SRC|DST|SPT|DPT|PROTO)=\S" // firewall key=value fields
        + @"|\[UFW\s|\bkernel:|\biptables\b|\bnftables\b|nf_tables",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    /// <summary>
    /// Returns true when the text contains at least <see cref="LogLineThreshold"/>
    /// non-empty lines that look like syslog/firewall log lines.
    /// </summary>
    public static bool HasLogIntent(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var matchingLines = 0;
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (LogLineRegex.IsMatch(line))
            {
                matchingLines++;
                if (matchingLines >= LogLineThreshold)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
