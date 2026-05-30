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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-001", Description);

        var value = data.SshConfig.PermitRootLogin;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-001", Description, Severity.Critical, "PermitRootLogin yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" });
        }

        return RuleResult.Pass(Id, Category, "SSH-001", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-002", Description);

        var value = data.SshConfig.PasswordAuthentication;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-002", Description, Severity.High, "PasswordAuthentication yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" });
        }

        return RuleResult.Pass(Id, Category, "SSH-002", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-003", Description);

        var value = data.SshConfig.MaxAuthTries;
        if (value == null || value > 4 || value == 0)
        {
            return RuleResult.Fail(Id, Category, "SSH-003", Description, Severity.Medium,
                value?.ToString() ?? "default",
                new Dictionary<string, string> { ["value"] = value?.ToString() ?? "default (6)" });
        }

        return RuleResult.Pass(Id, Category, "SSH-003", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-004", Description);

        var value = data.SshConfig.Protocol;
        if (!string.IsNullOrEmpty(value))
        {
            var protocols = value.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (protocols.Any(p => p.Equals("1", StringComparison.OrdinalIgnoreCase)))
            {
                return RuleResult.Fail(Id, Category, "SSH-004", Description, Severity.Critical,
                    $"Protocol {value}",
                    new Dictionary<string, string> { ["value"] = value });
            }
        }

        return RuleResult.Pass(Id, Category, "SSH-004", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-005", Description);

        var value = data.SshConfig.PermitEmptyPasswords;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-005", Description, Severity.Critical,
                "PermitEmptyPasswords yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" });
        }

        return RuleResult.Pass(Id, Category, "SSH-005", Description);
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

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-006", Description);

        var value = data.SshConfig.PubkeyAuthentication;
        if (string.Equals(value, "no", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-006", Description, Severity.High,
                "PubkeyAuthentication no",
                new Dictionary<string, string> { ["value"] = value ?? "no" });
        }

        return RuleResult.Pass(Id, Category, "SSH-006", Description);
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

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Server, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        if (data.SshConfig == null || !data.SshConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, "SSH-007", Description);

        // Workstations may intentionally use X11 forwarding.
        if (context.Role == MachineRole.Workstation)
            return RuleResult.Pass(Id, Category, "SSH-007", Description);

        var value = data.SshConfig.X11Forwarding;
        if (string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return RuleResult.Fail(Id, Category, "SSH-007", Description, Severity.Medium,
                "X11Forwarding yes",
                new Dictionary<string, string> { ["value"] = value ?? "yes" });
        }

        return RuleResult.Pass(Id, Category, "SSH-007", Description);
    }
}
