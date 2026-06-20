namespace VulcansTrace.Linux.Agent.Memory;

/// <summary>
/// Records one remediation attempt → verified fix → returned cycle for a rule.
/// </summary>
public sealed record RemediationCycle
{
    /// <summary>UTC timestamp when the remediation was attempted.</summary>
    public DateTime AttemptedUtc { get; init; }

    /// <summary>UTC timestamp when the rule was verified as fixed, if verification has happened.</summary>
    public DateTime? VerifiedFixedUtc { get; init; }

    /// <summary>UTC timestamp when the finding returned after verification, if closed.</summary>
    public DateTime? ReturnedUtc { get; init; }

    /// <summary>Sequential cycle number for this rule.</summary>
    public int CycleNumber { get; init; }

    /// <summary>True when the cycle has been closed by a return.</summary>
    public bool IsClosed => VerifiedFixedUtc.HasValue && ReturnedUtc.HasValue;
}
