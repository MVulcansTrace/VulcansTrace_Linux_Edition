using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class LoggingAuditMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1562.001", TechniqueName = "Impair Defenses: Disable or Modify Tools", Tactic = "Defense Evasion", WhyItMatters = "Missing or disabled logging tools impair security monitoring and forensic capabilities." },
        new MitreTechnique { TechniqueId = "T1070", TechniqueName = "Indicator Removal", Tactic = "Defense Evasion", WhyItMatters = "Inadequate logging allows attackers to remove indicators of their activity." },
    };
}


/// <summary>
/// LOG-001: A system logging service (rsyslog or journald) should be active.
/// </summary>
public sealed class LoggingServiceActiveRule : IRule
{
    public string Id => "LOG-001";
    public string Category => "Logging";
    public string Description => "A system logging service should be active";
    public string WhatItChecks => "Checks whether rsyslog or systemd-journald is active";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl is-active rsyslog", "systemctl is-active systemd-journald" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.1",
            ControlName = "Establish and Maintain an Audit Log Management Process",
            WhyItMatters = "Without an active logging service, security events are not captured. This is a core requirement in SOC 2, PCI-DSS 10.1, and HIPAA.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.2.1.1 — Ensure rsyslog or systemd-journald is installed"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (!data.LoggingAudit.RsyslogActive && !data.LoggingAudit.JournaldActive)
        {
            return RuleResult.Fail(Id, Category, "LOG-001", Description, Severity.Medium, "none",
                new Dictionary<string, string> { ["rsyslog"] = "inactive", ["journald"] = "inactive" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-001", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-002: auditd service should be active.
/// </summary>
public sealed class AuditdActiveRule : IRule
{
    public string Id => "LOG-002";
    public string Category => "Logging";
    public string Description => "auditd should be running";
    public string WhatItChecks => "Checks whether the auditd service is active";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl is-active auditd" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.2",
            ControlName = "Collect Audit Logs",
            WhyItMatters = "auditd captures security-relevant system events (privilege escalation, file access, authentication). Its absence means no forensic trail for compliance or incident response.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.1.1.1 — Ensure auditd is installed"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (!data.LoggingAudit.AuditdActive)
        {
            return RuleResult.Fail(Id, Category, "LOG-002", Description, Severity.High, "auditd",
                new Dictionary<string, string> { ["service"] = "auditd", ["status"] = "inactive" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-002", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-003: auditd should have active rules configured.
/// </summary>
public sealed class AuditdRulesConfiguredRule : IRule
{
    public string Id => "LOG-003";
    public string Category => "Logging";
    public string Description => "auditd should have active rules";
    public string WhatItChecks => "Checks whether auditd has at least one active rule";
    public IReadOnlyList<string> SupportedDataSources => new[] { "auditctl -l", "/etc/audit/audit.rules" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.2",
            ControlName = "Collect Audit Logs",
            WhyItMatters = "An auditd daemon with no rules records nothing. CIS and DISA STIG require rules for privilege escalation, authentication, file integrity, and unauthorized access attempts.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.1.3.x — Ensure events that modify date and time information are collected"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null || !string.IsNullOrEmpty(data.LoggingAudit.ReadWarning))
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (data.LoggingAudit.AuditdActive && !data.LoggingAudit.AuditdRulesConfigured)
        {
            return RuleResult.Fail(Id, Category, "LOG-003", Description, Severity.High, "auditd",
                new Dictionary<string, string>
                {
                    ["service"] = "auditd",
                    ["rules"] = "0",
                    ["hint"] = "Run 'auditctl -l' to verify; add rules to /etc/audit/audit.rules"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-003", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-004: Log rotation should be configured.
/// </summary>
public sealed class LogRotationConfiguredRule : IRule
{
    public string Id => "LOG-004";
    public string Category => "Logging";
    public string Description => "Log rotation should be configured";
    public string WhatItChecks => "Checks whether /etc/logrotate.conf or /etc/logrotate.d/ entries exist";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/logrotate.conf", "/etc/logrotate.d/" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.3",
            ControlName = "Collect Service Provider Logs",
            WhyItMatters = "Without log rotation, logs grow unbounded and can exhaust disk space, causing service outages and log loss. Log retention policies also require rotation.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.3.x — Ensure logrotate is configured"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (!data.LoggingAudit.LogRotationConfigured)
        {
            return RuleResult.Fail(Id, Category, "LOG-004", Description, Severity.Low, "logrotate",
                new Dictionary<string, string> { ["config"] = "missing" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-004", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-005: Central log forwarding should be configured.
/// </summary>
public sealed class CentralForwardingConfiguredRule : IRule, IContextualRule
{
    public string Id => "LOG-005";
    public string Category => "Logging";
    public string Description => "Central log forwarding should be configured";
    public string WhatItChecks => "Checks whether rsyslog forwards to a remote host or journald forwards to syslog";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf", "/etc/systemd/journald.conf" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.4",
            ControlName = "Collect Audit Log Details",
            WhyItMatters = "Logs stored only locally are lost during compromise or disk failure. Centralized logging (SIEM) is required by PCI-DSS 10.5, SOC 2, and most compliance frameworks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.2.2.x — Ensure rsyslog is configured to send logs to a remote log host"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Workstation, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        if (data.LoggingAudit == null)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        // Non-production roles may legitimately not forward centrally.
        if (context.Role is MachineRole.Workstation or MachineRole.DevMachine or MachineRole.LabBox or MachineRole.Router)
        {
            return RuleResult.Pass(Id, Category, "LOG-005", Description, CisMappings, MitreTechniques);
        }

        if (!data.LoggingAudit.CentralForwardingConfigured)
        {
            return RuleResult.Fail(Id, Category, "LOG-005", Description, Severity.Medium, "none",
                new Dictionary<string, string> { ["forwarding"] = "not configured" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-005", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-006: auditd should monitor privilege escalation syscalls.
/// </summary>
public sealed class AuditdPrivilegeEscalationMonitoringRule : IRule
{
    public string Id => "LOG-006";
    public string Category => "Logging";
    public string Description => "auditd should monitor privilege escalation syscalls";
    public string WhatItChecks => "Checks whether auditd rules monitor setuid, setgid, and related syscalls";
    public IReadOnlyList<string> SupportedDataSources => new[] { "auditctl -l", "/etc/audit/audit.rules" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.2",
            ControlName = "Collect Audit Logs",
            WhyItMatters = "Without monitoring setuid/setgid syscalls, privilege escalation attacks (sudo bypass, SUID exploitation) leave no audit trail. CIS and MITRE ATT&CK require syscall auditing for defense evasion detection.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.1.12 — Ensure successful file system mounts are collected"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    private static readonly string[] PrivEscSyscalls =
    {
        "setuid", "setgid", "seteuid", "setegid",
        "setreuid", "setregid", "setresuid", "setresgid"
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null || !string.IsNullOrEmpty(data.LoggingAudit.ReadWarning))
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        // If auditd has no rules at all, LOG-003 already flags that; defer to it.
        if (!data.LoggingAudit.AuditdRulesConfigured)
            return RuleResult.Pass(Id, Category, "LOG-006", Description, CisMappings, MitreTechniques);

        var rules = data.LoggingAudit.AuditdRules;
        var hasPrivEsc = rules.Any(r =>
            PrivEscSyscalls.Any(s =>
                r.Contains(s, StringComparison.OrdinalIgnoreCase)));

        if (!hasPrivEsc)
        {
            return RuleResult.Fail(Id, Category, "LOG-006", Description, Severity.High, "auditd",
                new Dictionary<string, string>
                {
                    ["service"] = "auditd",
                    ["rules"] = rules.Count.ToString(),
                    ["missing"] = string.Join(", ", PrivEscSyscalls),
                    ["hint"] = "Add: -a always,exit -F arch=b64 -S setuid,setgid,seteuid,setegid,setreuid,setregid,setresuid,setresgid -k privilege_escalation"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-006", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// LOG-007: Remote log forwarding should use TCP, not UDP.
/// </summary>
public sealed class ForwardingUsesTcpRule : IRule
{
    public string Id => "LOG-007";
    public string Category => "Logging";
    public string Description => "Remote log forwarding should use TCP";
    public string WhatItChecks => "Checks whether rsyslog forwarding targets use TCP (@@) instead of UDP (@)";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 8.4",
            ControlName = "Collect Audit Log Details",
            WhyItMatters = "UDP syslog forwarding is unreliable (no delivery guarantee) and transmits logs in plaintext without session integrity. TCP ensures reliable delivery and can be wrapped in TLS for encryption.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.2.2.x — Ensure rsyslog is configured to send logs to a remote log host"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => LoggingAuditMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.LoggingAudit == null)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = Id,
                Description = $"{Description} — logging/audit configuration not available (scanner failed or permission denied).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        // If no forwarding is configured, LOG-005 already flags that; defer to it.
        if (!data.LoggingAudit.CentralForwardingConfigured)
            return RuleResult.Pass(Id, Category, "LOG-007", Description, CisMappings, MitreTechniques);

        var udpTargets = data.LoggingAudit.ForwardingTargets
            .Where(t => t.StartsWith('@') && !t.StartsWith("@@"))
            .ToList();

        if (udpTargets.Count > 0)
        {
            return RuleResult.Fail(Id, Category, "LOG-007", Description, Severity.Medium, udpTargets.First(),
                new Dictionary<string, string>
                {
                    ["udp_targets"] = string.Join(", ", udpTargets),
                    ["count"] = udpTargets.Count.ToString(),
                    ["hint"] = "Replace @ with @@ in rsyslog forwarding directives to use TCP"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "LOG-007", Description, CisMappings, MitreTechniques);
    }
}
