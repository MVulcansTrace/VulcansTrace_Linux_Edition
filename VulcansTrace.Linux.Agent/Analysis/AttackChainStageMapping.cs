using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// Maps rule identifiers to deterministic kill-chain stages and rationales.
/// This is separate from the rule's MITRE technique list because the existing
/// mappings are coarse (e.g., all SSH rules share the same techniques).
/// </summary>
public static class AttackChainStageMapping
{
    /// <summary>
    /// Returns the stage mapping for a rule ID, or null if the rule is not part of a known chain.
    /// Supports wildcard suffix matching (e.g., PORT-*).
    /// </summary>
    public static AttackChainStageInfo? GetMapping(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return null;

        foreach (var mapping in Mappings)
        {
            if (Matches(ruleId, mapping.Key))
            {
                return mapping.Value;
            }
        }

        return null;
    }

    private static bool Matches(string ruleId, string pattern)
    {
        if (pattern.EndsWith("*", StringComparison.Ordinal))
        {
            var prefix = pattern[..^1];
            return ruleId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        return ruleId.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly IReadOnlyDictionary<string, AttackChainStageInfo> Mappings =
        new Dictionary<string, AttackChainStageInfo>(StringComparer.OrdinalIgnoreCase)
        {
            ["FW-002"] = new(AttackChainStage.Reconnaissance,
                "SSH is exposed to the internet, making the host visible to scanning and reconnaissance campaigns."),

            ["FW-004"] = new(AttackChainStage.Reconnaissance,
                "No active firewall removes the network perimeter, making the host reachable from any source."),

            ["PORT-*"] = new(AttackChainStage.InitialAccess,
                "Listening services expose entry points an attacker can reach once the network perimeter is gone."),

            ["USER-001"] = new(AttackChainStage.Execution,
                "Additional UID-0 accounts provide alternate root-level access paths and make privileged persistence harder to audit."),

            ["SSH-002"] = new(AttackChainStage.CredentialAccess,
                "Password authentication allows remote brute-force attempts against the exposed SSH service."),

            ["SSH-001"] = new(AttackChainStage.Execution,
                "PermitRootLogin allows an attacker who obtains root credentials to execute commands as root directly."),

            ["SSH-005"] = new(AttackChainStage.Execution,
                "PermitEmptyPasswords allows anyone to authenticate as an affected account without a credential."),

            ["SSH-006"] = new(AttackChainStage.CredentialAccess,
                "Disabling public-key authentication forces reliance on weaker password-based authentication."),
        };
}

/// <summary>
/// Describes a rule's role in an attack chain stage.
/// </summary>
public sealed record AttackChainStageInfo
{
    /// <summary>The kill-chain stage this rule belongs to.</summary>
    public AttackChainStage Stage { get; }

    /// <summary>Why this rule maps to the stage.</summary>
    public string Rationale { get; }

    /// <summary>Initializes a new <see cref="AttackChainStageInfo"/>.</summary>
    public AttackChainStageInfo(AttackChainStage stage, string rationale)
    {
        Stage = stage;
        Rationale = rationale;
    }
}
