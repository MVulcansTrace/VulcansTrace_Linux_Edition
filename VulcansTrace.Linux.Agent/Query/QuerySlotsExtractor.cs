using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Single, deterministic extractor for <see cref="QuerySlots"/>. Intent scoring stays in
/// <see cref="QueryParser"/>; this only captures modifiers (freshness, verbosity, category, finding
/// reference) so consumers stop re-scanning the raw query with ad-hoc keyword helpers.
/// </summary>
internal static class QuerySlotsExtractor
{
    private static readonly Regex RuleIdPattern = new(
        @"\b[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-\d+\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Extracts slots from a query. <paramref name="normalizedQuery"/> (lowercased) drives phrase
    /// matching; <paramref name="rawQuery"/> preserves case for the finding-reference capture;
    /// <paramref name="intent"/> supplies the canonical category for targeted audits.
    /// </summary>
    public static QuerySlots Extract(string normalizedQuery, string rawQuery, AgentIntent intent)
    {
        // An explicit prohibition is stronger than incidental refresh words inside the same
        // phrase ("do not scan again" contains both "scan" and "again"). Otherwise the exact
        // language intended to prevent a scan would be classified as ForceRefresh.
        var freshness = ContainsNoScanMarker(normalizedQuery) ? Freshness.ReuseOnly
            : ContainsRerunMarker(normalizedQuery) ? Freshness.ForceRefresh
            : ContainsReuseMarker(normalizedQuery) ? Freshness.ReuseOnly
            : Freshness.Auto;

        var verbosity = ContainsBrevityMarker(normalizedQuery) ? QueryVerbosity.Terse : QueryVerbosity.Normal;

        var ruleMatch = RuleIdPattern.Match(rawQuery);

        return new QuerySlots
        {
            Freshness = freshness,
            Verbosity = verbosity,
            Category = IntentCategoryMap.GetCategory(intent),
            FindingReference = ruleMatch.Success ? ruleMatch.Value : null
        };
    }

    private static bool ContainsBrevityMarker(string q)
    {
        return q.Contains("short version")
            || q.Contains("short answer")
            || q.Contains("quick version")
            || q.Contains("quick answer")
            || q.Contains("bottom line")
            || q.Contains("in short")
            || q.Contains("in brief")
            || q.Contains("tldr")
            || q.Contains("tl;dr")
            || q.Contains("summarize")
            || q.Contains("summary")
            || q.Contains("verdict")
            || ContainsWholeWord(q, "brief")
            || ContainsWholeWord(q, "concise");
    }

    private static bool ContainsRerunMarker(string q)
    {
        return q.Contains("re-run")
            || q.Contains("rerun")
            || q.Contains("re-scan")
            || q.Contains("rescan")
            || q.Contains("re-check")
            || q.Contains("recheck")
            || q.Contains("run again")
            || q.Contains("scan again")
            || q.Contains("check again")
            || q.Contains("fresh scan")
            || q.Contains("fresh audit")
            || q.Contains("fresh check")
            || ContainsWholeWord(q, "again")
            || ContainsWholeWord(q, "fresh");
    }

    private static bool ContainsNoScanMarker(string q)
    {
        return q.Contains("without rescanning")
            || q.Contains("without re-scanning")
            || q.Contains("without scanning")
            || q.Contains("do not scan again")
            || q.Contains("don't scan again")
            || q.Contains("dont scan again")
            || q.Contains("do not rescan")
            || q.Contains("don't rescan")
            || q.Contains("dont rescan");
    }

    private static bool ContainsReuseMarker(string q)
    {
        // Phrases that explicitly ask to answer from prior results without scanning. Kept clear of
        // ShowChanges ("what changed since the last audit") and FilterCategory phrasing, and
        // narrowed to mention the audit/results explicitly so they don't hijack unrelated contexts
        // (e.g. "what were the results" colliding with remediation-verification results).
        return q.Contains("what did you find")
            || q.Contains("what did the audit find")
            || q.Contains("what were the audit results")
            || q.Contains("what were the results of the audit")
            || q.Contains("what were the results of your audit")
            || q.Contains("from your audit")
            || q.Contains("based on your audit")
            || q.Contains("based on the last audit")
            || q.Contains("based on the audit")
            || ContainsNoScanMarker(q)
            || q.Contains("recap the audit")
            || q.Contains("recap the results")
            || q.Contains("recap the findings");
    }

    private static bool ContainsWholeWord(string text, string word)
    {
        var index = 0;
        while ((index = text.IndexOf(word, index, StringComparison.Ordinal)) >= 0)
        {
            var before = index == 0 || !char.IsLetterOrDigit(text[index - 1]);
            var afterIndex = index + word.Length;
            var after = afterIndex >= text.Length || !char.IsLetterOrDigit(text[afterIndex]);
            if (before && after)
                return true;

            index += word.Length;
        }

        return false;
    }
}
