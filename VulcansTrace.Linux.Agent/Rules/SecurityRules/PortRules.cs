using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class PortMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1046", TechniqueName = "Network Service Discovery", Tactic = "Discovery", WhyItMatters = "Open ports expose network services to discovery and exploitation." },
        new MitreTechnique { TechniqueId = "T1021", TechniqueName = "Remote Services", Tactic = "Lateral Movement", WhyItMatters = "Unnecessary listening services enable lateral movement." },
    };
}


/// <summary>
/// PORT-001: SSH should ideally run on a non-default port.
/// </summary>
public sealed class SshNonDefaultPortRule : IRule, IContextualRule
{
    public string Id => "PORT-001";
    public string Category => "Port";
    public string Description => "SSH on non-default port (informational)";
    public string WhatItChecks => "Checks whether SSH is running on the default port 22";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "netstat -tulnp" };
    public Severity Severity => Severity.Info;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "Running SSH on the default port 22 increases visibility to automated scanners. While not a control requirement, non-default ports reduce noise in logs and frustrate untargeted attacks."
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => PortMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        var sshPort = data.OpenPorts.FirstOrDefault(p => p.LocalPort == 22);
        if (sshPort != null)
        {
            if (context.Policy?.Parameters.TryGetValue("treatDefaultAs", out var treatDefaultAs) == true &&
                string.Equals(treatDefaultAs, "Pass", StringComparison.OrdinalIgnoreCase))
            {
                return RuleResult.Pass(Id, Category, "PORT-001", Description, CisMappings, MitreTechniques);
            }

            return RuleResult.Fail(Id, Category, "PORT-001", Description, Severity.Info, "22",
                new Dictionary<string, string> { ["port"] = "22" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "PORT-001", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// PORT-002: Services listening on 0.0.0.0/:: should be reviewed.
/// </summary>
public sealed class WideOpenServicesRule : IRule, IContextualRule
{
    public string Id => "PORT-002";
    public string Category => "Port";
    public string Description => "Services listening on all interfaces should be reviewed";
    public string WhatItChecks => "Checks for services listening on all interfaces that should be reviewed";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "netstat -tulnp" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Services bound to all interfaces increase the attack surface. Each listening port should have a documented business need and be protected by host or network firewall rules.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => PortMitreMappings.Techniques;

    private static readonly int[] DefaultExpectedPublicPorts = { 22, 80, 443 };

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        var expectedPorts = DefaultExpectedPublicPorts;
        if (context.Policy?.Parameters.TryGetValue("expectedPublicPorts", out var portsStr) == true)
        {
            expectedPorts = portsStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => int.TryParse(s.Trim(), out var p) ? p : (int?)null)
                .Where(p => p.HasValue)
                .Select(p => p!.Value)
                .ToArray();
        }

        var wideOpen = data.OpenPorts.Where(p =>
            p.LocalAddress is "0.0.0.0" or "::" &&
            p.State is "LISTEN" or "LISTENING" &&
            !expectedPorts.Contains(p.LocalPort)).ToList();

        if (wideOpen.Any())
        {
            var first = wideOpen.First();
            return RuleResult.Fail(Id, Category, "PORT-002", Description, Severity.Medium,
                $"{first.LocalAddress}:{first.LocalPort}",
                new Dictionary<string, string>
                {
                    ["port"] = first.LocalPort.ToString(),
                    ["address"] = first.LocalAddress,
                    ["process"] = first.ProcessName ?? "unknown",
                    ["count"] = wideOpen.Count.ToString()
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "PORT-002", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// PORT-003: Database ports exposed to all interfaces.
/// </summary>
public sealed class DatabasePortExposureRule : IRule
{
    public string Id => "PORT-003";
    public string Category => "Port";
    public string Description => "Database ports should not be exposed to all interfaces";
    public string WhatItChecks => "Checks whether database ports are exposed to all interfaces";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "netstat -tulnp" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Database ports exposed to all interfaces bypass defense-in-depth and violate data-protection requirements (PCI-DSS Req 1.3, HIPAA 164.312(e)).",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => PortMitreMappings.Techniques;

    private static readonly int[] DatabasePorts = { 3306, 5432, 27017, 1433, 1521, 6379 };

    public RuleResult Evaluate(ScanData data)
    {
        var exposed = data.OpenPorts.Where(p =>
            p.LocalAddress is "0.0.0.0" or "::" &&
            DatabasePorts.Contains(p.LocalPort)).ToList();

        if (exposed.Any())
        {
            var first = exposed.First();
            return RuleResult.Fail(Id, Category, "PORT-003", Description, Severity.Critical,
                $"{first.LocalAddress}:{first.LocalPort}",
                new Dictionary<string, string>
                {
                    ["port"] = first.LocalPort.ToString(),
                    ["process"] = first.ProcessName ?? "unknown"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "PORT-003", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// PORT-004: Unused high ports open without clear purpose.
/// </summary>
public sealed class HighPortListeningRule : IRule
{
    public string Id => "PORT-004";
    public string Category => "Port";
    public string Description => "High ports listening without clear process (informational)";
    public string WhatItChecks => "Checks for high ports listening without an associated process name";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ss -tulnp", "netstat -tulnp" };
    public Severity Severity => Severity.Info;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 13.3",
            ControlName = "Deploy a Network Intrusion Detection Solution",
            WhyItMatters = "Unattributed listening high ports may indicate unauthorized services, backdoors, or misconfigured applications that evade standard port monitoring.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.6 / 3.5.2.6 — Ensure firewall rules exist for all open ports"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => PortMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var highPorts = data.OpenPorts.Where(p =>
            p.LocalPort > 1024 &&
            p.LocalPort is not (3306 or 5432 or 27017 or 6379 or 8080 or 8443) &&
            string.IsNullOrEmpty(p.ProcessName) &&
            p.State is "LISTEN" or "LISTENING").ToList();

        if (highPorts.Any())
        {
            var first = highPorts.First();
            return RuleResult.Fail(Id, Category, "PORT-004", Description, Severity.Info,
                $"port {first.LocalPort}",
                new Dictionary<string, string>
                {
                    ["port"] = first.LocalPort.ToString(),
                    ["count"] = highPorts.Count.ToString()
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "PORT-004", Description, CisMappings, MitreTechniques);
    }
}
