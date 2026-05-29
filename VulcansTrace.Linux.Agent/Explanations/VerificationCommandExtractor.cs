using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Extracts copyable verification commands from structured explanation markdown.
/// </summary>
public static class VerificationCommandExtractor
{
    // Matches backtick-enclosed inline code: `command`
    private static readonly Regex BacktickPattern = new Regex(@"`([^`]+)`", RegexOptions.Compiled);

    // Matches numbered list lines that end with a command-like pattern:
    // e.g., "1. Check the current policy: `sudo iptables -L INPUT | head -n 1`"
    // or "1. `sudo iptables -L INPUT | head -n 1`"
    private static readonly Regex NumberedListPattern = new Regex(@"^\s*\d+\.\s*(?:[^`]*?\s*)?`([^`]+)`", RegexOptions.Compiled | RegexOptions.Multiline);

    /// <summary>
    /// Extracts copyable commands from the provided markdown text.
    /// </summary>
    /// <param name="markdown">The markdown text to parse.</param>
    /// <returns>A list of unique copyable commands in the order they appear.</returns>
    public static IReadOnlyList<CopyableCommand> Extract(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return Array.Empty<CopyableCommand>();

        var commands = new List<CopyableCommand>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // First, try to extract from numbered list items with backticks
        var numberedMatches = NumberedListPattern.Matches(markdown);
        foreach (Match match in numberedMatches)
        {
            var command = match.Groups[1].Value.Trim();
            if (!string.IsNullOrWhiteSpace(command) && seen.Add(command))
            {
                var analysis = CommandSafetyClassifier.Analyze(command);
                commands.Add(new CopyableCommand
                {
                    DisplayText = command,
                    FullCommand = command,
                    Safety = analysis.Safety,
                    Analysis = analysis
                });
            }
        }

        // If no numbered list commands found, fall back to all backtick patterns
        if (commands.Count == 0)
        {
            var backtickMatches = BacktickPattern.Matches(markdown);
            foreach (Match match in backtickMatches)
            {
                var command = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(command) && seen.Add(command))
                {
                    var analysis = CommandSafetyClassifier.Analyze(command);
                    commands.Add(new CopyableCommand
                    {
                        DisplayText = command,
                        FullCommand = command,
                        Safety = analysis.Safety,
                        Analysis = analysis
                    });
                }
            }
        }

        return commands;
    }

    /// <summary>
    /// Extracts copyable commands only from the "How to verify" section.
    /// </summary>
    /// <param name="markdown">The markdown text to parse.</param>
    /// <returns>A list of unique verification commands in the order they appear.</returns>
    public static IReadOnlyList<CopyableCommand> ExtractHowToVerify(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return Array.Empty<CopyableCommand>();

        var section = ExtractSection(markdown, "How to verify")
            ?? ExtractSection(markdown, "How to check");

        return string.IsNullOrWhiteSpace(section)
            ? Array.Empty<CopyableCommand>()
            : Extract(section);
    }

    private static string? ExtractSection(string markdown, string heading)
    {
        var escapedHeading = Regex.Escape(heading);
        var pattern = $@"\*\*{escapedHeading}:\*\*(.*?)(?=\n\*\*|\z)";
        var match = Regex.Match(markdown, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }
}
