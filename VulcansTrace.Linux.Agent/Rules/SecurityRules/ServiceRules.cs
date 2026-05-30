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
    public string WhatItChecks => "Checks whether the Telnet service is running";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-units --type=service --state=running" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "Telnet transmits credentials in plaintext. Its presence is a critical finding in PCI-DSS 2.3, HIPAA, and every major compliance framework.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.17 — Ensure telnet server is not installed"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        var telnet = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("telnet", StringComparison.OrdinalIgnoreCase));

        if (telnet != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-001", Description, Severity.Critical, telnet.Name,
                new Dictionary<string, string> { ["service"] = telnet.Name }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SRV-001", Description, CisMappings);
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
    public string WhatItChecks => "Checks whether the FTP service is running";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-units --type=service --state=running" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "FTP lacks encryption. Replacing it with SFTP is required by PCI-DSS 4.2.1 and HIPAA data-transmission controls.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.12 — Ensure FTP server is not installed"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        var ftp = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("ftp", StringComparison.OrdinalIgnoreCase) &&
            !s.Name.Contains("sftp", StringComparison.OrdinalIgnoreCase));

        if (ftp != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-002", Description, Severity.High, ftp.Name,
                new Dictionary<string, string> { ["service"] = ftp.Name }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SRV-002", Description, CisMappings);
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
    public string WhatItChecks => "Checks whether the SSH service is running";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-units --type=service --state=running" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "SSH is the standard secure remote-management channel for Linux servers. Its absence forces insecure alternatives (console, IPMI) or leaves the system unmanaged.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.4 — Ensure SSH server is installed and enabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        var ssh = data.RunningServices.FirstOrDefault(s =>
            s.Name.Contains("ssh", StringComparison.OrdinalIgnoreCase));

        if (ssh == null)
        {
            return RuleResult.Fail(Id, Category, "SRV-003", Description, Severity.Medium, "ssh",
                new Dictionary<string, string>(), CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SRV-003", Description, CisMappings);
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
    public string WhatItChecks => "Checks whether legacy r-services (rsh, rexec, rlogin) are running";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-units --type=service --state=running" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "Legacy r-services rely on weak host-based trust (rhosts) and transmit data unencrypted. They have been obsolete for decades and are an automatic critical audit failure.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.16 — Ensure rsh server is not installed"
        }
    };

    private static readonly string[] LegacyServices = { "rsh", "rexec", "rlogin", "shell", "login", "exec" };

    public RuleResult Evaluate(ScanData data)
    {
        var found = data.RunningServices.FirstOrDefault(s =>
            LegacyServices.Any(l => s.Name.Contains(l, StringComparison.OrdinalIgnoreCase)));

        if (found != null)
        {
            return RuleResult.Fail(Id, Category, "SRV-004", Description, Severity.Critical, found.Name,
                new Dictionary<string, string> { ["service"] = found.Name }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SRV-004", Description, CisMappings);
    }
}

/// <summary>
/// SRV-005: Unnecessary services that expand attack surface.
/// </summary>
public sealed class UnnecessaryServicesRule : IRule, IContextualRule
{
    public string Id => "SRV-005";
    public string Category => "Service";
    public string Description => "Unnecessary services should be disabled";
    public string WhatItChecks => "Checks whether unnecessary services (CUPS, Avahi, Bluetooth, NFS, RPC, SMB) are running";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-units --type=service --state=running" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "Each running service is a potential exploitation target. Disabling unnecessary services is a core attack-surface reduction principle in CIS, PCI-DSS, and DISA STIGs.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2.x — Ensure unnecessary services are removed or disabled"
        }
    };

    private static readonly string[] DefaultUnnecessaryServices =
    {
        "cups", "avahi", "bluetooth", "nfs", "rpcbind", "smb", "nmb"
    };

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        var services = DefaultUnnecessaryServices.ToList();
        if (context.Policy?.Parameters.TryGetValue("ignoredServices", out var ignoredStr) == true)
        {
            var ignored = ignoredStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            services.RemoveAll(s => ignored.Contains(s));
        }

        var found = data.RunningServices.Where(s =>
            services.Any(u => s.Name.Contains(u, StringComparison.OrdinalIgnoreCase))).ToList();

        if (found.Any())
        {
            var first = found.First();
            return RuleResult.Fail(Id, Category, "SRV-005", Description, Severity.Low, first.Name,
                new Dictionary<string, string>
                {
                    ["service"] = first.Name,
                    ["count"] = found.Count.ToString()
                }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SRV-005", Description, CisMappings);
    }
}
