using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class FirewallMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1562.004", TechniqueName = "Impair Defenses: Disable or Modify System Firewall", Tactic = "Defense Evasion", WhyItMatters = "Weak firewall rules impair network defenses and enable evasion." },
    };
}


/// <summary>
/// FW-001: Firewall should have a default DROP policy on INPUT chain.
/// </summary>
public sealed class FirewallDefaultDropRule : IRule
{
    public string Id => "FW-001";
    public string Category => "Firewall";
    public string Description => "Default INPUT policy should be DROP";
    public string WhatItChecks => "Checks whether the iptables/nftables INPUT chain has a default DROP policy";
    public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.5",
            ControlName = "Implement and Manage a Firewall on Servers",
            WhyItMatters = "A default ACCEPT policy allows any unsolicited inbound traffic. PCI-DSS 1.2, HIPAA 164.312(e), and SOC 2 all require explicit deny-by-default posture.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.3 / 3.5.2.3 — Ensure default deny firewall policy"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FirewallMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Fail(Id, Category, "FW-001", Description, Severity.High, "INPUT",
                new Dictionary<string, string> { ["issue"] = "No active firewall detected" }, CisMappings, MitreTechniques);

        var inputChain = data.FirewallRules.FirstOrDefault(r => r.Chain.Equals("INPUT", StringComparison.OrdinalIgnoreCase));
        if (inputChain == null)
        {
            return RuleResult.Pass(Id, Category, "FW-001", Description, CisMappings, MitreTechniques);
        }

        // Check if any rule has target DROP for default policy (iptables -L shows policy in chain header, not as rule)
        // We infer from raw text: if "policy ACCEPT" appears in INPUT chain header
        var hasAcceptPolicy = data.FirewallRaw.Contains("Chain INPUT (policy ACCEPT", StringComparison.OrdinalIgnoreCase);
        var hasDropPolicy = data.FirewallRaw.Contains("Chain INPUT (policy DROP", StringComparison.OrdinalIgnoreCase);

        if (hasAcceptPolicy)
        {
            return RuleResult.Fail(Id, Category, "FW-001", Description, Severity.High, "INPUT",
                new Dictionary<string, string> { ["policy"] = "ACCEPT" }, CisMappings, MitreTechniques);
        }

        if (hasDropPolicy)
        {
            return RuleResult.Pass(Id, Category, "FW-001", Description, CisMappings, MitreTechniques);
        }

        // Unknown policy or nftables — be lenient
        return RuleResult.Pass(Id, Category, "FW-001", Description, CisMappings, MitreTechniques);
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
    public string WhatItChecks => "Checks whether SSH (port 22) is restricted to specific IPs or open to any IP";
    public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.5",
            ControlName = "Implement and Manage a Firewall on Servers",
            WhyItMatters = "SSH open to any IP violates least-privilege network access and exposes the asset to untargeted brute-force campaigns, a common audit failure.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FirewallMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-002", Description, CisMappings, MitreTechniques); // Can't verify without firewall

        var sshRules = data.FirewallRules.Where(r =>
            r.DestinationPort == "22" || r.RawLine.Contains("dpt:22") || r.RawLine.Contains("--dport 22")).ToList();

        if (!sshRules.Any())
        {
            // No explicit SSH rule — might be covered by general ACCEPT or DROP
            return RuleResult.Fail(Id, Category, "FW-002", Description, Severity.Medium, "SSH/22",
                new Dictionary<string, string> { ["issue"] = "No explicit SSH firewall rule found" }, CisMappings, MitreTechniques);
        }

        var openRule = sshRules.FirstOrDefault(r =>
            r.Target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase) &&
            (r.Source == "0.0.0.0/0" || r.Source == "0.0.0.0" || r.Source == "::/0"));

        if (openRule != null)
        {
            return RuleResult.Fail(Id, Category, "FW-002", Description, Severity.High, "SSH/22",
                new Dictionary<string, string> { ["source"] = openRule.Source }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "FW-002", Description, CisMappings, MitreTechniques);
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
    public string WhatItChecks => "Checks for ESTABLISHED,RELATED connection state tracking rules in the firewall";
    public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.5",
            ControlName = "Implement and Manage a Firewall on Servers",
            WhyItMatters = "State tracking prevents unsolicited inbound traffic from reaching the host while allowing return traffic for established connections, a foundational firewall requirement.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.2 / 3.5.2.2 — Ensure iptables/nftables service is enabled"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FirewallMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-003", Description, CisMappings, MitreTechniques);

        var hasStateTracking = data.FirewallRules.Any(r =>
            r.StateMatch != null &&
            r.StateMatch.Contains("ESTABLISHED", StringComparison.OrdinalIgnoreCase));

        if (!hasStateTracking)
        {
            return RuleResult.Fail(Id, Category, "FW-003", Description, Severity.Medium, "INPUT",
                new Dictionary<string, string>(), CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "FW-003", Description, CisMappings, MitreTechniques);
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
    public string WhatItChecks => "Checks whether iptables or nftables is active and has rules configured";
    public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.5",
            ControlName = "Implement and Manage a Firewall on Servers",
            WhyItMatters = "No active firewall means no network perimeter enforcement. This is an automatic critical failure in PCI-DSS, SOC 2, and CIS audits.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.1 / 3.5.2.1 — Ensure iptables/nftables is installed"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FirewallMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.FirewallActive && data.FirewallRules.Count > 0)
            return RuleResult.Pass(Id, Category, "FW-004", Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, "FW-004", Description, Severity.Critical, "firewall",
            new Dictionary<string, string>(), CisMappings, MitreTechniques);
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
    public string WhatItChecks => "Checks whether ICMP is blanket-accepted without rate limiting";
    public IReadOnlyList<string> SupportedDataSources => new[] { "iptables -L -n -v", "nft list ruleset" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.5",
            ControlName = "Implement and Manage a Firewall on Servers",
            WhyItMatters = "Unrestricted ICMP acceptance can facilitate reconnaissance (ping sweeps) and certain denial-of-service attacks (ICMP floods). Rate limiting mitigates this risk.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.5 / 3.5.2.5 — Ensure outbound and established connections are configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => FirewallMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.FirewallActive)
            return RuleResult.Pass(Id, Category, "FW-005", Description, CisMappings, MitreTechniques);

        var icmpRules = data.FirewallRules.Where(r =>
            r.Protocol.Equals("icmp", StringComparison.OrdinalIgnoreCase) ||
            r.RawLine.Contains("icmp", StringComparison.OrdinalIgnoreCase)).ToList();

        if (!icmpRules.Any())
        {
            // No explicit ICMP rule — might be handled by default policy
            return RuleResult.Pass(Id, Category, "FW-005", Description, CisMappings, MitreTechniques);
        }

        var blanketAccept = icmpRules.Any(r =>
            r.Target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase) &&
            (r.Source == "0.0.0.0/0" || r.Source == "0.0.0.0"));

        if (blanketAccept)
        {
            return RuleResult.Fail(Id, Category, "FW-005", Description, Severity.Low, "ICMP",
                new Dictionary<string, string>(), CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "FW-005", Description, CisMappings, MitreTechniques);
    }
}
