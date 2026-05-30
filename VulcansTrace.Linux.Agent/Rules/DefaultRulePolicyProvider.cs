using System.Collections.Immutable;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Provides built-in default policies per role, with an optional override provider
/// for user-supplied policy.
/// </summary>
public sealed class DefaultRulePolicyProvider : IRulePolicyProvider
{
    private readonly IRulePolicyProvider? _overrideProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultRulePolicyProvider"/> class.
    /// </summary>
    /// <param name="overrideProvider">Optional override provider (e.g., JSON file store).</param>
    public DefaultRulePolicyProvider(IRulePolicyProvider? overrideProvider = null)
    {
        _overrideProvider = overrideProvider;
    }

    /// <inheritdoc />
    public RulePolicy? GetPolicy(string ruleId, MachineRole role)
    {
        var builtInPolicy = GetBuiltInPolicy(ruleId, role);
        var overridePolicy = _overrideProvider?.GetPolicy(ruleId, role);

        if (builtInPolicy != null && overridePolicy != null)
            return Merge(builtInPolicy, overridePolicy);

        return overridePolicy ?? builtInPolicy;
    }

    private static RulePolicy Merge(RulePolicy builtInPolicy, RulePolicy overridePolicy)
    {
        return new RulePolicy
        {
            Enabled = overridePolicy.Enabled ?? builtInPolicy.Enabled,
            SeverityOverride = overridePolicy.SeverityOverride ?? builtInPolicy.SeverityOverride,
            AutoPass = overridePolicy.AutoPass ?? builtInPolicy.AutoPass,
            Parameters = builtInPolicy.Parameters.SetItems(overridePolicy.Parameters)
        };
    }

    private static RulePolicy? GetBuiltInPolicy(string ruleId, MachineRole role)
    {
        return (ruleId, role) switch
        {
            // Server / Router: stricter — SSH on default port is discouraged
            ("PORT-001", MachineRole.Server) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Fail" }.ToImmutableDictionary()
            },
            ("PORT-001", MachineRole.Router) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Fail" }.ToImmutableDictionary()
            },

            // Workstation / DevMachine / LabBox: looser — SSH on 22 is acceptable
            ("PORT-001", MachineRole.Workstation) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Pass" }.ToImmutableDictionary()
            },
            ("PORT-001", MachineRole.DevMachine) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Pass" }.ToImmutableDictionary()
            },
            ("PORT-001", MachineRole.LabBox) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Pass" }.ToImmutableDictionary()
            },

            // DevMachine: looser on wide-open services (add common dev ports)
            ("PORT-002", MachineRole.DevMachine) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["expectedPublicPorts"] = "22,80,443,8080,8443" }.ToImmutableDictionary()
            },

            // DevMachine: looser on unnecessary services (ignore nfs, smb)
            ("SRV-005", MachineRole.DevMachine) => new RulePolicy
            {
                Parameters = new Dictionary<string, string> { ["ignoredServices"] = "nfs,smb" }.ToImmutableDictionary()
            },

            _ => null
        };
    }
}
