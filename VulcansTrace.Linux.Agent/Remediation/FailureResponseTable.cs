using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Rules;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Maps failure categories to deterministic fallback guidance.
/// Supports category-level defaults and rule-specific overrides.
/// </summary>
public sealed class FailureResponseTable
{
    private readonly FailureClassifier _classifier = new();

    /// <summary>
    /// Builds a human-readable response for a failed step.
    /// </summary>
    /// <param name="ruleId">The rule ID of the step that failed.</param>
    /// <param name="failureReason">The cleaned failure text reported by the user.</param>
    /// <param name="attemptedCommand">Optional command that was attempted.</param>
    /// <param name="originalErrorText">Optional original message text, used as a classification fallback when the cleaned reason loses trigger words.</param>
    /// <returns>Adaptive guidance that cites the failure category and step context.</returns>
    public string BuildResponse(string? ruleId, string? failureReason, string? attemptedCommand = null, string? originalErrorText = null)
    {
        var category = _classifier.Classify(failureReason);
        if (category == FailureCategory.UnknownFailure && !string.IsNullOrWhiteSpace(originalErrorText))
        {
            category = _classifier.Classify(originalErrorText);
        }
        var commandRef = !string.IsNullOrWhiteSpace(attemptedCommand)
            ? $"`{attemptedCommand.Trim()}`"
            : "the command";

        var categoryResponse = category switch
        {
            FailureCategory.MissingDependency => BuildMissingDependencyResponse(ruleId, commandRef),
            FailureCategory.PermissionIssue => $"{commandRef} needs elevated privileges. Try running it with `sudo`. If you're already root, check whether the target file is immutable: `lsattr <path>`.",
            FailureCategory.AlreadyConfigured => $"The configuration appears to already be in place or conflicts with an existing setting. You can skip this step and move to the next one, or review {commandRef} to confirm it matches your intent.",
            FailureCategory.ServiceMissing => $"The referenced service isn't installed or isn't loaded. Install the package and enable it with `systemctl enable --now <service>`, then retry {commandRef}.",
            FailureCategory.MalformedCommand => $"There may be a syntax issue in {commandRef}. Verify the command for typos, missing arguments, or unsupported options, then retry.",
            FailureCategory.UnknownFailure or _ => null
        };

        if (string.IsNullOrWhiteSpace(categoryResponse))
        {
            var fallback = !string.IsNullOrWhiteSpace(ruleId)
                ? RuleCategoryResolver.GetGuidance(ruleId)
                : "I couldn't determine the exact failure type. Review the command output and try again, or skip this step if the change is already applied.";

            var titlePrefix = !string.IsNullOrWhiteSpace(ruleId)
                ? $"**[{ruleId}] Step failed**"
                : "**Step failed**";

            return $"{titlePrefix} (UnknownFailure) — I couldn't classify the error. {fallback}";
        }

        var prefix = !string.IsNullOrWhiteSpace(ruleId)
            ? $"**[{ruleId}] Step failed**"
            : "**Step failed**";

        return $"{prefix} ({category}): {categoryResponse}";
    }

    private static string BuildMissingDependencyResponse(string? ruleId, string commandRef)
    {
        if (!string.IsNullOrWhiteSpace(ruleId))
        {
            var prefix = ruleId.Split('-')[0].ToUpperInvariant();
            if (prefix is "FW" or "FIREWALL")
            {
                return $"A firewall tool isn't available for {commandRef}. Install `iptables` or `nftables` first, then re-run the step.";
            }

            if (prefix is "SSH")
            {
                return $"The SSH server package may not be installed. Install `openssh-server` first, then re-run {commandRef}.";
            }

            if (prefix is "SRV" or "SERVICE")
            {
                return $"The service package isn't installed. Install it with your package manager, then re-run {commandRef}.";
            }
        }

        return $"A required tool or package is missing for {commandRef}. Install the dependency, then retry the step.";
    }
}
