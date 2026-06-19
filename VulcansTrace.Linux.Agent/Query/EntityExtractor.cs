using System.Text.RegularExpressions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Deterministic entity extractor for agent queries.
/// Uses regex and keyword matching; no external NLP dependencies.
/// </summary>
public sealed class EntityExtractor : IEntityExtractor
{
    private static readonly Regex RuleIdPattern = new(@"[A-Za-z]{2,}-\d{3,}", RegexOptions.Compiled);
    private static readonly Regex SessionIdPattern = new(@"\b[0-9a-fA-F]{8}\b", RegexOptions.Compiled);
    private static readonly Regex OrdinalPattern = new(@"\b(?:the\s+)?(first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|1st|2nd|3rd|4th|5th|6th|7th|8th|9th|10th)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DaysAgoPattern = new(@"last\s+(\d+)\s+days?", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex WeeksAgoPattern = new(@"last\s+week", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex TodayPattern = new(@"\btoday\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly HashSet<string> CategoryKeywords = new(QueryParser.CategoryKeywords, StringComparer.OrdinalIgnoreCase);

    private static readonly Dictionary<string, Severity> SeverityKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        ["critical"] = Severity.Critical,
        ["crit"] = Severity.Critical,
        ["high"] = Severity.High,
        ["medium"] = Severity.Medium,
        ["med"] = Severity.Medium,
        ["low"] = Severity.Low,
        ["info"] = Severity.Info,
        ["informational"] = Severity.Info
    };

    private static readonly Dictionary<string, AgentIntent> RemediationVerbKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        ["fix"] = AgentIntent.FixFinding,
        ["resolve"] = AgentIntent.FixFinding,
        ["remediate"] = AgentIntent.StartRemediation,
        ["walk me through"] = AgentIntent.StartRemediation,
        ["verify"] = AgentIntent.VerifyRemediation,
        ["explain"] = AgentIntent.ExplainFinding,
        ["what does"] = AgentIntent.ExplainFinding,
        ["why"] = AgentIntent.ExplainFinding,
        ["resume"] = AgentIntent.ResumeRemediation,
        ["continue"] = AgentIntent.ResumeRemediation
    };

    /// <inheritdoc />
    public QueryEntityFrame Extract(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new QueryEntityFrame();

        var normalized = query.ToLowerInvariant().Trim();
        var tokens = Tokenize(normalized);

        return new QueryEntityFrame
        {
            RuleIds = ExtractRuleIds(query),
            Categories = ExtractCategories(normalized),
            SessionId = ExtractSessionId(query),
            SeverityFilter = ExtractSeverity(tokens),
            TimeWindow = ExtractTimeWindow(normalized),
            RemediationVerb = ExtractRemediationVerb(normalized),
            OrdinalReference = ExtractOrdinal(normalized),
            Tokens = tokens
        };
    }

    private static IReadOnlyList<string> ExtractRuleIds(string query)
    {
        return RuleIdPattern.Matches(query)
            .Select(m => m.Value.ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<string> ExtractCategories(string normalized)
    {
        return CategoryKeywords
            .Where(k => normalized.Contains(k, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? ExtractSessionId(string query)
    {
        var match = SessionIdPattern.Match(query);
        return match.Success ? match.Value : null;
    }

    private static Severity? ExtractSeverity(IReadOnlyList<string> tokens)
    {
        foreach (var token in tokens)
        {
            if (SeverityKeywords.TryGetValue(token, out var severity))
                return severity;
        }

        return null;
    }

    private static TimeSpan? ExtractTimeWindow(string normalized)
    {
        if (DaysAgoPattern.IsMatch(normalized))
        {
            var match = DaysAgoPattern.Match(normalized);
            if (int.TryParse(match.Groups[1].Value, out var days))
                return TimeSpan.FromDays(days);
        }

        if (WeeksAgoPattern.IsMatch(normalized))
            return TimeSpan.FromDays(7);

        if (TodayPattern.IsMatch(normalized))
            return TimeSpan.FromDays(1);

        return null;
    }

    private static AgentIntent? ExtractRemediationVerb(string normalized)
    {
        foreach (var (phrase, intent) in RemediationVerbKeywords)
        {
            if (MatchesPhrase(normalized, phrase))
                return intent;
        }

        return null;
    }

    private static bool MatchesPhrase(string normalized, string phrase)
    {
        // Multi-word phrases must appear as a contiguous substring bounded by
        // word boundaries or string boundaries.
        if (phrase.Contains(' '))
        {
            var index = normalized.IndexOf(phrase, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
                return false;

            var before = index == 0 || !char.IsLetterOrDigit(normalized[index - 1]);
            var after = index + phrase.Length >= normalized.Length
                || !char.IsLetterOrDigit(normalized[index + phrase.Length]);
            return before && after;
        }

        // Single-word verbs must appear as whole words.
        var pattern = $"\\b{Regex.Escape(phrase)}\\b";
        return Regex.IsMatch(normalized, pattern, RegexOptions.IgnoreCase);
    }

    private static int? ExtractOrdinal(string normalized)
    {
        var match = OrdinalPattern.Match(normalized);
        if (!match.Success)
            return null;

        return match.Groups[1].Value.ToLowerInvariant() switch
        {
            "first" or "1st" => 1,
            "second" or "2nd" => 2,
            "third" or "3rd" => 3,
            "fourth" or "4th" => 4,
            "fifth" or "5th" => 5,
            "sixth" or "6th" => 6,
            "seventh" or "7th" => 7,
            "eighth" or "8th" => 8,
            "ninth" or "9th" => 9,
            "tenth" or "10th" => 10,
            _ => null
        };
    }

    private static IReadOnlyList<string> Tokenize(string normalized)
    {
        return normalized
            .Split(new[] { ' ', '\t', '\r', '\n', '.', ',', ';', ':', '?', '!' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim('\'', '"'))
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .ToList();
    }
}
