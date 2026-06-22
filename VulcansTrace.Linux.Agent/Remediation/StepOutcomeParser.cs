using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Parses user messages that report the outcome of a remediation step.
/// Deterministic — no ML or LLM.
/// </summary>
public sealed class StepOutcomeParser
{
    private static readonly Regex StepOrdinalPattern = new(
        @"\bstep\s+(?<ordinal>\d+)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RuleIdPattern = new(
        @"\b(?<rule>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-\d+)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] SuccessPhrases =
    {
        "done", "worked", "it worked", "that worked", "works", "succeeded", "completed",
        "finished", "all good", "no issues", "fixed", "resolved", "step done"
    };

    private static readonly string[] FailurePhrases =
    {
        "failed", "didn't work", "did not work", "doesn't work", "does not work",
        "not worked", "never worked",
        "failed with", "error", "permission denied", "command not found",
        "not installed", "service not found", "syntax error", "invalid argument"
    };

    /// <summary>
    /// Parses a raw user message into a structured step outcome report.
    /// </summary>
    public StepOutcomeReport Parse(string? rawQuery)
    {
        if (string.IsNullOrWhiteSpace(rawQuery))
            return new StepOutcomeReport { Kind = StepOutcomeKind.Failure };

        var text = rawQuery;

        var ordinal = ExtractOrdinal(text);
        var ruleId = ExtractRuleId(text);
        var kind = DetermineKind(text);
        var failureReason = kind == StepOutcomeKind.Failure ? ExtractFailureReason(text) : null;

        return new StepOutcomeReport
        {
            Kind = kind,
            StepOrdinal = ordinal,
            RuleId = ruleId,
            FailureReason = failureReason
        };
    }

    private static int? ExtractOrdinal(string text)
    {
        var match = StepOrdinalPattern.Match(text);
        if (match.Success && int.TryParse(match.Groups["ordinal"].Value, out var ordinal))
            return ordinal;
        return null;
    }

    private static string? ExtractRuleId(string text)
    {
        var match = RuleIdPattern.Match(text);
        return match.Success ? match.Groups["rule"].Value.ToUpperInvariant() : null;
    }

    private static StepOutcomeKind DetermineKind(string text)
    {
        var lower = text.ToLowerInvariant();

        // Any explicit failure signal other than the bare word "error" decides failure
        // first. This lets negated error phrases ("no error", "error-free") be treated
        // as success below without being overridden by the bare "error" entry.
        var hasFailureOtherThanError = FailurePhrases
            .Where(p => p != "error")
            .Any(p => lower.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (hasFailureOtherThanError)
            return StepOutcomeKind.Failure;

        // "no error" / "error-free" report success despite containing "error".
        if (NegatedErrorSuccessPattern.IsMatch(lower))
            return StepOutcomeKind.Success;

        if (FailurePhrases.Any(p => lower.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return StepOutcomeKind.Failure;

        if (SuccessPhrases.Any(p => lower.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return StepOutcomeKind.Success;

        // Neutral defaults: if the user only says "step 2" without success/failure words,
        // treat it as a failure report to be safe.
        return StepOutcomeKind.Failure;
    }

    private static readonly Regex FailureTriggerPattern = new(
        @"(failed(?:\s*(?:with|because|due to|:|\-))?|didn'?t work(?:\s*(?:because|due to|:|\-))?|doesn'?t work|error(?:\s*:)?|permission denied)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TrailingSessionReferencePattern = new(
        @"\s+((in|for)\s+session\s+\S+)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex NegatedErrorSuccessPattern = new(
        @"\b(?:no|without|zero)\s+errors?\b|\berror-?free\b|\berrors?\s+free\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string? ExtractFailureReason(string text)
    {
        // Capture the reason that follows the first explicit failure trigger.
        var match = FailureTriggerPattern.Match(text);
        if (!match.Success)
        {
            // No trigger found — fall back to trimming leading noise.
            var fallback = text;
            var prefixes = new[] { "step", "failure", ":", "-" };
            foreach (var prefix in prefixes)
            {
                fallback = Regex.Replace(fallback, $@"^\s*{Regex.Escape(prefix)}\b", string.Empty, RegexOptions.IgnoreCase);
            }
            fallback = TrailingSessionReferencePattern.Replace(fallback, string.Empty);
            fallback = fallback.Trim(' ', ':', '-', '—');
            return string.IsNullOrWhiteSpace(fallback) ? null : fallback;
        }

        var reason = text[(match.Index + match.Length)..];
        reason = TrailingSessionReferencePattern.Replace(reason, string.Empty);
        reason = reason.Trim(' ', ':', '-', '—');
        return string.IsNullOrWhiteSpace(reason) ? null : reason;
    }
}
