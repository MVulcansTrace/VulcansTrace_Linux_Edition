using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Deterministic, regex-based classifier for remediation step failure text.
/// No LLM or external NLP is used.
/// </summary>
public sealed class FailureClassifier
{
    private static readonly (Regex Pattern, FailureCategory Category)[] Patterns =
    {
        // Service-related missing patterns must come before the generic MissingDependency
        // matcher so that "service not found", "unit not found", and service-specific
        // "not installed" / "could not be found" phrases are not misclassified.
        (new Regex(@"\b(service not found|unit not found|failed to start|could not start|service is unknown|no such service|systemctl:\s*.*not loaded|service\b.*?\b(not installed|isn't installed|is not installed|could not be found)|unit\b.*?\b(not installed|isn't installed|is not installed|could not be found))\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), FailureCategory.ServiceMissing),
        (new Regex(@"\b(command not found|not installed|isn't installed|no such file|missing package|package not found|could not find|could not be found)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), FailureCategory.MissingDependency),
        (new Regex(@"\b(permission denied|operation not permitted|access denied|unauthorized|not allowed|cannot access|read-only file system|root required|sudo required)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), FailureCategory.PermissionIssue),
        (new Regex(@"\b(already exists|already configured|already set|already done|duplicate|conflict|overlaps with)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), FailureCategory.AlreadyConfigured),
        (new Regex(@"\b(syntax error|invalid argument|unrecognized option|unknown option|bad option|parse error|missing operand|usage:|malformed)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled), FailureCategory.MalformedCommand)
    };

    /// <summary>
    /// Classifies the provided failure text into a failure category.
    /// Returns <see cref="FailureCategory.UnknownFailure"/> when no pattern matches.
    /// </summary>
    public FailureCategory Classify(string? errorText)
    {
        if (string.IsNullOrWhiteSpace(errorText))
            return FailureCategory.UnknownFailure;

        foreach (var (pattern, category) in Patterns)
        {
            if (pattern.IsMatch(errorText))
                return category;
        }

        return FailureCategory.UnknownFailure;
    }
}
