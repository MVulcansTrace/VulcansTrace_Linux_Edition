using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class NetworkMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1021", TechniqueName = "Remote Services", Tactic = "Lateral Movement", WhyItMatters = "Network misconfigurations enable unauthorized remote access." },
        new MitreTechnique { TechniqueId = "T1071", TechniqueName = "Application Layer Protocol", Tactic = "Command and Control", WhyItMatters = "Poor network controls allow C2 communication channels." },
        new MitreTechnique { TechniqueId = "T1011", TechniqueName = "Exfiltration Over Other Network Medium", Tactic = "Exfiltration", WhyItMatters = "Misconfigured routing can facilitate data exfiltration." },
    };
}


/// <summary>
/// NET-001: A default gateway/route should be configured.
/// </summary>
public sealed class DefaultRouteRule : IRule
{
    public string Id => "NET-001";
    public string Category => "Network";
    public string Description => "A default gateway should be configured";
    public string WhatItChecks => "Checks whether a default gateway/route is configured";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ip route" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "A missing default gateway may indicate an incomplete network configuration or an isolated system with unintended connectivity gaps, complicating patching and monitoring."
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => NetworkMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var hasDefaultRoute = data.Routes.Any(r =>
            r.Destination == "default" || r.Destination == "0.0.0.0/0");

        if (!hasDefaultRoute)
        {
            return RuleResult.Fail(Id, Category, "NET-001", Description, Severity.Medium, "routing",
                new Dictionary<string, string>(), CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "NET-001", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// NET-002: Suspicious outbound connections to high-risk ports (telnet, SMB, RDP).
/// </summary>
public sealed class SuspiciousConnectionsRule : IRule
{
    public string Id => "NET-002";
    public string Category => "Network";
    public string Description => "Suspicious outbound connections to high-risk ports";
    public string WhatItChecks => "Checks for suspicious outbound connections to high-risk ports (telnet, SMB, RDP)";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tunap" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 13.3",
            ControlName = "Deploy a Network Intrusion Detection Solution",
            WhyItMatters = "Outbound connections to high-risk ports may indicate data exfiltration or C2 activity, a key concern for incident-response readiness and SOC 2 CC7.2."
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => NetworkMitreMappings.Techniques;

    private static readonly int[] SuspiciousPorts = { 23, 445, 3389, 135, 139 };

    public RuleResult Evaluate(ScanData data)
    {
        var suspicious = data.ActiveConnections.Where(c =>
            SuspiciousPorts.Contains(c.RemotePort) &&
            c.State is "ESTAB" or "ESTABLISHED").ToList();

        if (suspicious.Any())
        {
            var first = suspicious.First();
            return RuleResult.Fail(Id, Category, "NET-002", Description, Severity.High,
                $"{first.RemoteAddress}:{first.RemotePort}",
                new Dictionary<string, string>
                {
                    ["remote"] = $"{first.RemoteAddress}:{first.RemotePort}",
                    ["local"] = $"{first.LocalAddress}:{first.LocalPort}",
                    ["count"] = suspicious.Count.ToString()
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "NET-002", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// NET-003: At least one network interface should be up.
/// </summary>
public sealed class NetworkInterfaceUpRule : IRule
{
    public string Id => "NET-003";
    public string Category => "Network";
    public string Description => "At least one network interface should be up";
    public string WhatItChecks => "Checks whether at least one network interface is up";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ip addr" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "No active network interface may indicate a misconfigured or disabled system, preventing remote management, monitoring, and timely security updates."
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => NetworkMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.NetworkInterfaces.Any(i => i.IsUp))
        {
            return RuleResult.Fail(Id, Category, "NET-003", Description, Severity.High, "interfaces",
                new Dictionary<string, string>(), CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "NET-003", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// NET-004: Loopback (127.0.0.1) services should not be exposed on external interfaces.
/// </summary>
public sealed class LoopbackExposureRule : IRule
{
    public string Id => "NET-004";
    public string Category => "Network";
    public string Description => "Loopback-only services should not listen on all interfaces";
    public string WhatItChecks => "Checks whether loopback-only services are exposed on external interfaces";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "netstat -tulnp" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Services intended for loopback-only access (e.g., databases, debug ports) exposed externally bypass network segmentation and create direct attack vectors.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.4 / 3.5.2.4 — Ensure loopback traffic is configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => NetworkMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var loopbackPorts = data.OpenPorts
            .Where(p => p.LocalAddress is "127.0.0.1" or "::1")
            .Select(p => p.LocalPort)
            .Distinct()
            .ToHashSet();

        var exposedLoopback = data.OpenPorts
            .Where(p => p.LocalAddress is "0.0.0.0" or "::" && loopbackPorts.Contains(p.LocalPort))
            .ToList();

        if (exposedLoopback.Any())
        {
            var first = exposedLoopback.First();
            return RuleResult.Fail(Id, Category, "NET-004", Description, Severity.Medium,
                $"{first.LocalAddress}:{first.LocalPort}",
                new Dictionary<string, string>
                {
                    ["port"] = first.LocalPort.ToString(),
                    ["address"] = first.LocalAddress,
                    ["process"] = first.ProcessName ?? "unknown"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "NET-004", Description, CisMappings, MitreTechniques);
    }
}
