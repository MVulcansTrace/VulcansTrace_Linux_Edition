using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Rules;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Deterministic matcher that maps a user's diagnostic answer to a root-cause explanation.
/// </summary>
public sealed class RootCauseMatcher
{
    private static readonly Regex ConfigManagementPattern = new(
        @"\b(ansible|puppet|chef|salt|saltstack|cloud-init|terraform|pulumi)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RebootPattern = new(
        @"\b(reboot|restart|update|upgrade|patch|system update|apt upgrade|yum update|dnf update)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex UncertaintyPattern = new(
        @"\b(i don'?t know|not sure|unsure|no idea|not certain)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Matches the user's answer to a root cause for the specified rule.
    /// </summary>
    public RootCauseMatch Match(string answer, string ruleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(answer);
        ArgumentException.ThrowIfNullOrEmpty(ruleId);

        if (UncertaintyPattern.IsMatch(answer))
        {
            return new RootCauseMatch
            {
                Category = RootCauseCategory.Uncertain,
                Explanation = $"That's OK. {RuleCategoryResolver.GetGuidance(ruleId)}",
                SourceIds = new[] { ruleId }
            };
        }

        if (ConfigManagementPattern.IsMatch(answer))
        {
            return new RootCauseMatch
            {
                Category = RootCauseCategory.ConfigManagement,
                Explanation = "Your config-management tool is likely the source. It reapplies the insecure configuration on every run. Fix the template, playbook, or cloud-init user-data rather than the live system, then re-run the remediation.",
                SourceIds = new[] { ruleId }
            };
        }

        if (RebootPattern.IsMatch(answer))
        {
            return new RootCauseMatch
            {
                Category = RootCauseCategory.NonPersistent,
                Explanation = "The change doesn't persist across reboots or updates. Check that the setting is saved in the right configuration file, that the relevant service is enabled for boot-time startup, and that initramfs or base-image defaults aren't overriding it.",
                SourceIds = new[] { ruleId }
            };
        }

        return new RootCauseMatch
        {
            Category = RootCauseCategory.Unknown,
            Explanation = $"I couldn't match your answer to a known root-cause pattern. {RuleCategoryResolver.GetGuidance(ruleId)}",
            SourceIds = new[] { ruleId }
        };
    }
}

/// <summary>
/// The kind of root cause matched from a diagnostic answer.
/// </summary>
public enum RootCauseCategory
{
    Unknown,
    ConfigManagement,
    NonPersistent,
    Uncertain
}

/// <summary>
/// Result of matching a diagnostic answer to a root cause.
/// </summary>
public sealed record RootCauseMatch
{
    /// <summary>The matched root-cause category.</summary>
    public required RootCauseCategory Category { get; init; }

    /// <summary>Human-readable root-cause explanation.</summary>
    public required string Explanation { get; init; }

    /// <summary>Source IDs cited by the explanation (rule IDs, posture patterns, etc.).</summary>
    public required IReadOnlyList<string> SourceIds { get; init; }
}
