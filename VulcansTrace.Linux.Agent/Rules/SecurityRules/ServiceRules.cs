using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

/// <summary>
/// SRV-001: Telnet service should not be running.
/// </summary>
public sealed class TelnetServiceRule : IRule
{
    public string Id => "SRV-001";
    public string Category => "Service";
    public string Description => "Telnet should not be running";

    public RuleResult Evaluate(ScanData data)
    {
        var telnet = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("telnet", StringComparison.OrdinalIgnoreCase));

        if (telnet != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-001", Description, Severity.Critical, telnet.Name,
                new Dictionary<string, string> { ["service"] = telnet.Name });
        }

        return RuleResult.Pass(Id, Category, "SRV-001", Description);
    }
}

/// <summary>
/// SRV-002: FTP service should not be running.
/// </summary>
public sealed class FtpServiceRule : IRule
{
    public string Id => "SRV-002";
    public string Category => "Service";
    public string Description => "FTP should not be running (use SFTP instead)";

    public RuleResult Evaluate(ScanData data)
    {
        var ftp = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("ftp", StringComparison.OrdinalIgnoreCase) &&
            !s.Name.Contains("sftp", StringComparison.OrdinalIgnoreCase));

        if (ftp != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-002", Description, Severity.High, ftp.Name,
                new Dictionary<string, string> { ["service"] = ftp.Name });
        }

        return RuleResult.Pass(Id, Category, "SRV-002", Description);
    }
}

/// <summary>
/// SRV-003: SSH service should be running for remote access.
/// </summary>
public sealed class SshServiceRule : IRule
{
    public string Id => "SRV-003";
    public string Category => "Service";
    public string Description => "SSH should be running";

    public RuleResult Evaluate(ScanData data)
    {
        var ssh = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("ssh", StringComparison.OrdinalIgnoreCase));

        if (ssh == null)
        {
            return RuleResult.Fail(Id, Category, "SRV-003", Description, Severity.Medium, "ssh",
                new Dictionary<string, string>());
        }

        return RuleResult.Pass(Id, Category, "SRV-003", Description);
    }
}

/// <summary>
/// SRV-004: Legacy r-services (rsh, rexec, rlogin) should not be running.
/// </summary>
public sealed class LegacyRservicesRule : IRule
{
    public string Id => "SRV-004";
    public string Category => "Service";
    public string Description => "Legacy r-services should not be running";

    private static readonly string[] LegacyServices = { "rsh", "rexec", "rlogin", "shell", "login", "exec" };

    public RuleResult Evaluate(ScanData data)
    {
        var found = data.RunningServices.FirstOrDefault(s =>
            LegacyServices.Any(l => s.Name.Contains(l, StringComparison.OrdinalIgnoreCase)));

        if (found != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-004", Description, Severity.Critical, found.Name,
                new Dictionary<string, string> { ["service"] = found.Name });
        }

        return RuleResult.Pass(Id, Category, "SRV-004", Description);
    }
}

/// <summary>
/// SRV-005: Unnecessary services that expand attack surface.
/// </summary>
public sealed class UnnecessaryServicesRule : IRule
{
    public string Id => "SRV-005";
    public string Category => "Service";
    public string Description => "Unnecessary services should be disabled";

    private static readonly string[] UnnecessaryServices =
    {
        "cups", "avahi", "bluetooth", "nfs", "rpcbind", "smb", "nmb"
    };

    public RuleResult Evaluate(ScanData data)
    {
        var found = data.RunningServices.Where(s =>
            UnnecessaryServices.Any(u => s.Name.Contains(u, StringComparison.OrdinalIgnoreCase))).ToList();

        if (found.Any())
        {
            var first = found.First();
            return RuleResult.Fail(Id, Category, "SRV-005", Description, Severity.Low, first.Name,
                new Dictionary<string, string>
                {
                    ["service"] = first.Name,
                    ["count"] = found.Count.ToString()
                });
        }

        return RuleResult.Pass(Id, Category, "SRV-005", Description);
    }
}
