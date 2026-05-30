namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Provides <see cref="RulePolicy"/> lookups for a given rule and machine role.
/// </summary>
public interface IRulePolicyProvider
{
    /// <summary>
    /// Gets the policy for the specified rule and role, or <c>null</c> if none is configured.
    /// </summary>
    /// <param name="ruleId">The rule identifier.</param>
    /// <param name="role">The machine role.</param>
    /// <returns>The applicable policy, or <c>null</c>.</returns>
    RulePolicy? GetPolicy(string ruleId, MachineRole role);
}
