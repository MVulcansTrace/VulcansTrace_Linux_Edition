using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

/// <summary>
/// NET-001: A default gateway/route should be configured.
/// </summary>
public sealed class DefaultRouteRule : IRule
{
    public string Id => "NET-001";
    public string Category => "Network";
    public string Description => "A default gateway should be configured";

    public RuleResult Evaluate(ScanData data)
    {
        var hasDefaultRoute = data.Routes.Any(r =>
            r.Destination == "default" || r.Destination == "0.0.0.0/0");

        if (!hasDefaultRoute)
        {
            return RuleResult.Fail(Id, Category, "NET-001", Description, Severity.Medium, "routing",
                new Dictionary<string, string>());
        }

        return RuleResult.Pass(Id, Category, "NET-001", Description);
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
                });
        }

        return RuleResult.Pass(Id, Category, "NET-002", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (!data.NetworkInterfaces.Any(i => i.IsUp))
        {
            return RuleResult.Fail(Id, Category, "NET-003", Description, Severity.High, "interfaces",
                new Dictionary<string, string>());
        }

        return RuleResult.Pass(Id, Category, "NET-003", Description);
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
                });
        }

        return RuleResult.Pass(Id, Category, "NET-004", Description);
    }
}
