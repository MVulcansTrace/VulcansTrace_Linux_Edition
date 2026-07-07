namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Describes the outcome of saving a rule policy override.
/// </summary>
public sealed record RulePolicySaveResult(RulePolicySaveOutcome Outcome, string? Message = null)
{
    /// <summary>Gets whether the requested policy is now active in this process.</summary>
    public bool Applied => Outcome is RulePolicySaveOutcome.Durable or RulePolicySaveOutcome.SessionOnly;

    /// <summary>Gets whether the requested policy was written to durable storage.</summary>
    public bool Durable => Outcome == RulePolicySaveOutcome.Durable;

    /// <summary>Creates a durable-save result.</summary>
    public static RulePolicySaveResult SavedDurably() => new(RulePolicySaveOutcome.Durable);

    /// <summary>Creates a session-only result for an applied policy that was not written durably.</summary>
    public static RulePolicySaveResult SavedForSession(string message) => new(RulePolicySaveOutcome.SessionOnly, message);

    /// <summary>Creates a rejected result for a policy that was not applied.</summary>
    public static RulePolicySaveResult Rejected(string message) => new(RulePolicySaveOutcome.Rejected, message);
}

/// <summary>
/// High-level outcome for a rule-policy save request.
/// </summary>
public enum RulePolicySaveOutcome
{
    /// <summary>The policy is active and was written to durable storage.</summary>
    Durable,

    /// <summary>The policy is active for this process only.</summary>
    SessionOnly,

    /// <summary>The policy was rejected and the previous active policy remains unchanged.</summary>
    Rejected
}
