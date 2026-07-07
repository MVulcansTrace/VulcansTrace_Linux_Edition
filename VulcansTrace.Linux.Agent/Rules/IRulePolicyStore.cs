using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Mutable store for per-role rule policies.
/// </summary>
public interface IRulePolicyStore : IRulePolicyProvider
{
    /// <summary>
    /// Sets the policy for the specified rule and role.
    /// </summary>
    /// <param name="ruleId">The rule identifier.</param>
    /// <param name="role">The machine role.</param>
    /// <param name="policy">The policy to store.</param>
    /// <returns>The save outcome, including whether the change is durable, session-only, or rejected.</returns>
    RulePolicySaveResult SetPolicy(string ruleId, MachineRole role, RulePolicy policy);

    /// <summary>
    /// A human-readable warning describing the most recent persistence issue, or
    /// <c>null</c> when there is no warning to surface. Mutating calls return a
    /// <see cref="RulePolicySaveResult"/>; this property mirrors the latest warning for
    /// existing status surfaces.
    /// </summary>
    string? PersistenceWarning { get; }
}
