using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

/// <summary>
/// PORT-001: SSH should ideally run on a non-default port.
/// </summary>
public sealed class SshNonDefaultPortRule : IRule
{
    public string Id => "PORT-001";
    public string Category => "Port";
    public string Description => "SSH on non-default port (informational)";

    public RuleResult Evaluate(ScanData data)
    {
        var sshPort = data.OpenPorts.FirstOrDefault(p => p.LocalPort == 22);
        if (sshPort != null)
        {
            return RuleResult.Fail(Id, Category, "PORT-001", Description, Severity.Info, "22",
                new Dictionary<string, string> { ["port"] = "22" });
        }

        return RuleResult.Pass(Id, Category, "PORT-001", Description);
    }
}

/// <summary>
/// PORT-002: Services listening on 0.0.0.0/:: should be reviewed.
/// </summary>
public sealed class WideOpenServicesRule : IRule
{
    public string Id => "PORT-002";
    public string Category => "Port";
    public string Description => "Services listening on all interfaces should be reviewed";

    private static readonly int[] ExpectedPublicPorts = { 22, 80, 443 };

    public RuleResult Evaluate(ScanData data)
    {
        var wideOpen = data.OpenPorts.Where(p =>
            p.LocalAddress is "0.0.0.0" or "::" &&
            p.State is "LISTEN" or "LISTENING" &&
            !ExpectedPublicPorts.Contains(p.LocalPort)).ToList();

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
                });
        }

        return RuleResult.Pass(Id, Category, "PORT-002", Description);
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
                });
        }

        return RuleResult.Pass(Id, Category, "PORT-003", Description);
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
                });
        }

        return RuleResult.Pass(Id, Category, "PORT-004", Description);
    }
}
