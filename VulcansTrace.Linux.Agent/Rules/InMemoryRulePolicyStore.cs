using System.Collections.Concurrent;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// An in-memory rule policy store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryRulePolicyStore : IRulePolicyProvider
{
    private readonly ConcurrentDictionary<string, RulePolicy> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Sets a policy for the given rule and role.
    /// </summary>
    /// <param name="ruleId">The rule identifier.</param>
    /// <param name="role">The machine role.</param>
    /// <param name="policy">The policy to store.</param>
    public void SetPolicy(string ruleId, MachineRole role, RulePolicy policy)
    {
        _entries[$"{ruleId}|{role}"] = policy;
    }

    /// <inheritdoc />
    public RulePolicy? GetPolicy(string ruleId, MachineRole role)
    {
        _entries.TryGetValue($"{ruleId}|{role}", out var policy);
        return policy;
    }
}
