using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

/// <summary>
/// SSH-001: PermitRootLogin should not be enabled.
/// </summary>
public sealed class SshPermitRootLoginRule : IRule
{
    public string Id => "SSH-001";
    public string Category => "SSH";
    public string Description => "PermitRootLogin should be disabled or set to prohibit-password";
    public string WhatItChecks => "Checks whether SSH permits direct root login with a password";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.4",
            ControlName = "Restrict Administrator Privileges",
            WhyItMatters = "PermitRootLogin removes individual accountability and prevents audit trails from attributing actions to a specific identity, violating PCI-DSS 8.2 and SOC 2 CC6.1.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.7 — Ensure SSH root login is disabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-001", Description, CisMappings);

        var value = data.SshConfig.PermitRootLogin;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-001", Description, Severity.Critical, "PermitRootLogin yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-001", Description, CisMappings);
    }
}

/// <summary>
/// SSH-002: PasswordAuthentication should be disabled in favor of key-based auth.
/// </summary>
public sealed class SshPasswordAuthenticationRule : IRule
{
    public string Id => "SSH-002";
    public string Category => "SSH";
    public string Description => "PasswordAuthentication should be disabled (prefer key-based auth)";
    public string WhatItChecks => "Checks whether SSH password authentication is enabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.3",
            ControlName = "Require MFA for Externally-Exposed Applications",
            WhyItMatters = "Password authentication is susceptible to brute-force and credential-stuffing. Key-based authentication is the compliance baseline for remote access under NIST 800-53 IA-2.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.16 — Ensure SSH PasswordAuthentication is disabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-002", Description, CisMappings);

        var value = data.SshConfig.PasswordAuthentication;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-002", Description, Severity.High, "PasswordAuthentication yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-002", Description, CisMappings);
    }
}

/// <summary>
/// SSH-003: MaxAuthTries should be set to a low value (4 or less).
/// </summary>
public sealed class SshMaxAuthTriesRule : IRule
{
    public string Id => "SSH-003";
    public string Category => "SSH";
    public string Description => "MaxAuthTries should be 4 or lower";
    public string WhatItChecks => "Checks whether SSH MaxAuthTries is set to a low value to mitigate brute force";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.3",
            ControlName = "Require MFA for Externally-Exposed Applications",
            WhyItMatters = "Unlimited or high authentication attempts enable brute-force attacks. Limiting MaxAuthTries to 4 or less is a scored item in CIS Linux benchmarks and reduces credential-guessing windows.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.14 — Ensure SSH MaxAuthTries is configured"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-003", Description, CisMappings);

        var value = data.SshConfig.MaxAuthTries;
        if (value == null || value > 4 || value == 0)
        {
            return RuleResult.Fail(Id, Category, "SSH-003", Description, Severity.Medium,
                value?.ToString() ?? "default",
                new Dictionary<string, string> { ["value"] = value?.ToString() ?? "default (6)" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-003", Description, CisMappings);
    }
}

/// <summary>
/// SSH-004: Protocol 1 should not be used.
/// </summary>
public sealed class SshProtocolRule : IRule
{
    public string Id => "SSH-004";
    public string Category => "SSH";
    public string Description => "SSH Protocol 1 should not be enabled";
    public string WhatItChecks => "Checks whether the legacy SSH Protocol 1 is configured";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "SSH Protocol 1 has known cryptographic weaknesses (CRC-32 integrity, weak key exchange) and has been deprecated for over two decades. Its presence is an automatic critical audit failure.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.15 — Ensure SSH Protocol is set to 2"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-004", Description, CisMappings);

        var value = data.SshConfig.Protocol;
        if (!string.IsNullOrEmpty(value))
        {
            var protocols = value.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (protocols.Any(p => p.Equals("1", StringComparison.OrdinalIgnoreCase)))
            {
                return RuleResult.Fail(Id, Category, "SSH-004", Description, Severity.Critical,
                    $"Protocol {value}",
                    new Dictionary<string, string> { ["value"] = value }, CisMappings);
            }
        }

        return RuleResult.Pass(Id, Category, "SSH-004", Description, CisMappings);
    }
}

/// <summary>
/// SSH-005: PermitEmptyPasswords should be disabled.
/// </summary>
public sealed class SshEmptyPasswordsRule : IRule
{
    public string Id => "SSH-005";
    public string Category => "SSH";
    public string Description => "PermitEmptyPasswords should be disabled";
    public string WhatItChecks => "Checks whether SSH allows empty passwords";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2",
            ControlName = "Use Unique Passwords",
            WhyItMatters = "Empty passwords eliminate authentication entirely. This is an automatic audit failure under PCI-DSS 8.2.3, HIPAA 164.312(a), and SOC 2 CC6.1.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-005", Description, CisMappings);

        var value = data.SshConfig.PermitEmptyPasswords;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-005", Description, Severity.Critical,
                "PermitEmptyPasswords yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-005", Description, CisMappings);
    }
}

/// <summary>
/// SSH-006: PubkeyAuthentication should be enabled.
/// </summary>
public sealed class SshPubkeyAuthenticationRule : IRule
{
    public string Id => "SSH-006";
    public string Category => "SSH";
    public string Description => "PubkeyAuthentication should be enabled";
    public string WhatItChecks => "Checks whether SSH public-key authentication is enabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 6.3",
            ControlName = "Require MFA for Externally-Exposed Applications",
            WhyItMatters = "Disabling public-key authentication forces reliance on weaker password-based methods, increasing exposure to brute-force and credential-stuffing attacks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.17 — Ensure SSH PubkeyAuthentication is enabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-006", Description, CisMappings);

        var value = data.SshConfig.PubkeyAuthentication;
        if (string.Equals(value, "no", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-006", Description, Severity.High,
                "PubkeyAuthentication no",
                new Dictionary<string, string> { ["value"] = value ?? "no" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-006", Description, CisMappings);
    }
}

/// <summary>
/// SSH-007: X11Forwarding should be disabled on servers.
/// </summary>
public sealed class SshX11ForwardingRule : IRule, IContextualRule
{
    public string Id => "SSH-007";
    public string Category => "SSH";
    public string Description => "X11Forwarding should be disabled";
    public string WhatItChecks => "Checks whether SSH X11 forwarding is enabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.8",
            ControlName = "Uninstall or Disable Unnecessary Services",
            WhyItMatters = "X11 forwarding over SSH tunnels graphical sessions, expanding the attack surface and potentially leaking display credentials. Servers should disable it unless explicitly required.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.12 — Ensure SSH X11 forwarding is disabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-007", Description, CisMappings);

        // Workstations may intentionally use X11 forwarding.
        if (context.Role == MachineRole.Workstation)
            return RuleResult.Pass(Id, Category, "SSH-007", Description, CisMappings);

        var value = data.SshConfig.X11Forwarding;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-007", Description, Severity.Medium,
                "X11Forwarding yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-007", Description, CisMappings);
    }
}

/// <summary>
/// SSH-008: UsePAM should be enabled to enforce local PAM policies (password quality, lockout, session).
/// </summary>
public sealed class SshUsePamRule : IRule
{
    public string Id => "SSH-008";
    public string Category => "SSH";
    public string Description => "SSH UsePAM should be enabled";
    public string WhatItChecks => "Checks whether SSH daemon is configured to use PAM for authentication and session management";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/ssh/sshd_config", "sshd -T" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2",
            ControlName = "Configure SSH Server",
            WhyItMatters = "Disabling UsePAM causes SSH to bypass local PAM policies including password quality, account lockout, and session logging. This creates a gap where users can authenticate with weaker credentials than the host policy requires.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.20 — Ensure SSH PAM is enabled"
        }
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.NotApplicable(Id, Category, "SSH-008", Description, CisMappings);

        var value = data.SshConfig.UsePAM;
        // OpenSSH defaults UsePAM to yes; only fail when explicitly disabled.
        if (string.Equals(value, "no", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-008", Description, Severity,
                "UsePAM no",
                new Dictionary<string, string> { ["value"] = value ?? "no" }, CisMappings);
        }

        return RuleResult.Pass(Id, Category, "SSH-008", Description, CisMappings);
    }
}
