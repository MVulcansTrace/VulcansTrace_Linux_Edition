using System.Collections.Concurrent;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// An in-memory rule policy store that does not persist across process restarts.
/// </summary>
public sealed class InMemoryRulePolicyStore : IRulePolicyStore
{
    private readonly ConcurrentDictionary<string, RulePolicy> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _sessionOnlyWarning;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryRulePolicyStore"/> class.
    /// </summary>
    /// <param name="sessionOnlyWarning">
    /// Optional warning returned from saves when this store is used as a non-durable fallback.
    /// </param>
    public InMemoryRulePolicyStore(string? sessionOnlyWarning = null)
    {
        _sessionOnlyWarning = string.IsNullOrWhiteSpace(sessionOnlyWarning) ? null : sessionOnlyWarning;
    }

    /// <inheritdoc />
    public RulePolicySaveResult SetPolicy(string ruleId, MachineRole role, RulePolicy policy)
    {
        _entries[$"{ruleId}|{role}"] = policy;
        return _sessionOnlyWarning is null
            ? RulePolicySaveResult.SavedDurably()
            : RulePolicySaveResult.SavedForSession(_sessionOnlyWarning);
    }

    /// <inheritdoc />
    public RulePolicy? GetPolicy(string ruleId, MachineRole role)
    {
        _entries.TryGetValue($"{ruleId}|{role}", out var policy);
        return policy;
    }

    /// <inheritdoc />
    public string? PersistenceWarning => _sessionOnlyWarning;
}
