using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

/// <summary>
/// FW-001: Firewall should have a default DROP policy on INPUT chain.
/// </summary>
public sealed class FirewallDefaultDropRule : IRule
{
    public string Id => "FW-001";
    public string Category => "Firewall";
    public string Description => "Default INPUT policy should be DROP";

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Fail(Id, Category, "FW-001", Description, Severity.High, "INPUT",
                new Dictionary<string, string> { ["issue"] = "No active firewall detected" });

        var inputChain = data.FirewallRules.FirstOrDefault(r => r.Chain.Equals("INPUT", StringComparison.OrdinalIgnoreCase));
        if (inputChain == null)
        {
            return RuleResult.Pass(Id, Category, "FW-001", Description);
        }

        // Check if any rule has target DROP for default policy (iptables -L shows policy in chain header, not as rule)
        // We infer from raw text: if "policy ACCEPT" appears in INPUT chain header
        var hasAcceptPolicy = data.FirewallRaw.Contains("Chain INPUT (policy ACCEPT", StringComparison.OrdinalIgnoreCase);
        var hasDropPolicy = data.FirewallRaw.Contains("Chain INPUT (policy DROP", StringComparison.OrdinalIgnoreCase);

        if (hasAcceptPolicy)
        {
            return RuleResult.Fail(Id, Category, "FW-001", Description, Severity.High, "INPUT",
                new Dictionary<string, string> { ["policy"] = "ACCEPT" });
        }

        if (hasDropPolicy)
        {
            return RuleResult.Pass(Id, Category, "FW-001", Description);
        }

        // Unknown policy or nftables — be lenient
        return RuleResult.Pass(Id, Category, "FW-001", Description);
    }
}

/// <summary>
/// FW-002: SSH (port 22) should not be exposed to 0.0.0.0/0 without restriction.
/// </summary>
public sealed class FirewallSshExposureRule : IRule
{
    public string Id => "FW-002";
    public string Category => "Firewall";
    public string Description => "SSH should be restricted, not open to any IP";

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-002", Description); // Can't verify without firewall

        var sshRules = data.FirewallRules.Where(r =>
            r.DestinationPort == "22" || r.RawLine.Contains("dpt:22") || r.RawLine.Contains("--dport 22")).ToList();

        if (!sshRules.Any())
        {
            // No explicit SSH rule — might be covered by general ACCEPT or DROP
            return RuleResult.Fail(Id, Category, "FW-002", Description, Severity.Medium, "SSH/22",
                new Dictionary<string, string> { ["issue"] = "No explicit SSH firewall rule found" });
        }

        var openRule = sshRules.FirstOrDefault(r =>
            r.Target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase) &&
            (r.Source == "0.0.0.0/0" || r.Source == "0.0.0.0" || r.Source == "::/0"));

        if (openRule != null)
        {
            return RuleResult.Fail(Id, Category, "FW-002", Description, Severity.High, "SSH/22",
                new Dictionary<string, string> { ["source"] = openRule.Source });
        }

        return RuleResult.Pass(Id, Category, "FW-002", Description);
    }
}

/// <summary>
/// FW-003: ESTABLISHED,RELATED state tracking should be present.
/// </summary>
public sealed class FirewallStateTrackingRule : IRule
{
    public string Id => "FW-003";
    public string Category => "Firewall";
    public string Description => "Connection state tracking (ESTABLISHED,RELATED) should be enabled";

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-003", Description);

        var hasStateTracking = data.FirewallRules.Any(r =>
            r.StateMatch != null &&
            r.StateMatch.Contains("ESTABLISHED", StringComparison.OrdinalIgnoreCase));

        if (!hasStateTracking)
        {
            return RuleResult.Fail(Id, Category, "FW-003", Description, Severity.Medium, "INPUT",
                new Dictionary<string, string>());
        }

        return RuleResult.Pass(Id, Category, "FW-003", Description);
    }
}

/// <summary>
/// FW-004: Firewall should be active (iptables or nftables has rules).
/// </summary>
public sealed class FirewallActiveRule : IRule
{
    public string Id => "FW-004";
    public string Category => "Firewall";
    public string Description => "A firewall (iptables or nftables) should be active";

    public RuleResult Evaluate(ScanData data)
    {
        if (data.FirewallActive && data.FirewallRules.Count > 0)
            return RuleResult.Pass(Id, Category, "FW-004", Description);

        return RuleResult.Fail(Id, Category, "FW-004", Description, Severity.Critical, "firewall",
            new Dictionary<string, string>());
    }
}

/// <summary>
/// FW-005: ICMP should not be blanket-accepted without rate limiting.
/// </summary>
public sealed class FirewallIcmpRule : IRule
{
    public string Id => "FW-005";
    public string Category => "Firewall";
    public string Description => "ICMP should be restricted or rate-limited";

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-005", Description);

        var icmpRules = data.FirewallRules.Where(r =>
            r.Protocol.Equals("icmp", StringComparison.OrdinalIgnoreCase) ||
            r.RawLine.Contains("icmp", StringComparison.OrdinalIgnoreCase)).ToList();

        if (!icmpRules.Any())
        {
            // No explicit ICMP rule — might be handled by default policy
            return RuleResult.Pass(Id, Category, "FW-005", Description);
        }

        var blanketAccept = icmpRules.Any(r =>
            r.Target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase) &&
            (r.Source == "0.0.0.0/0" || r.Source == "0.0.0.0"));

        if (blanketAccept)
        {
            return RuleResult.Fail(Id, Category, "FW-005", Description, Severity.Low, "ICMP",
                new Dictionary<string, string>());
        }

        return RuleResult.Pass(Id, Category, "FW-005", Description);
    }
}
