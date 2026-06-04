using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class KernelHardeningMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1068", TechniqueName = "Exploitation for Privilege Escalation", Tactic = "Privilege Escalation", WhyItMatters = "Weak kernel hardening enables exploitation for privilege escalation." },
        new MitreTechnique { TechniqueId = "T1547.006", TechniqueName = "Boot or Logon Autostart Execution: Kernel Modules and Extensions", Tactic = "Persistence", WhyItMatters = "Unrestricted kernel modules allow persistent kernel-level compromise." },
    };
}


/// <summary>
/// KERN-001: Address Space Layout Randomization (ASLR) should be fully enabled.
/// </summary>
public sealed class AslrEnabledRule : IRule
{
    public string Id => "KERN-001";
    public string Category => "Kernel";
    public string Description => "ASLR should be fully enabled (kernel.randomize_va_space = 2)";
    public string WhatItChecks => "Checks whether Address Space Layout Randomization is fully enabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/kernel/randomize_va_space", "sysctl -a" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 1.5",
            ControlName = "Address Space Layout Randomization",
            WhyItMatters = "ASLR makes memory corruption exploits significantly harder by randomizing the memory locations used by system and program components. Without it, attackers can reliably jump to known addresses.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.5.2 — Ensure address space layout randomization is enabled"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-001", Description, CisMappings, MitreTechniques);

        if (kp.RandomizeVaSpace.GetValueOrDefault(0) < 2)
        {
            return RuleResult.Fail(Id, Category, "KERN-001", Description, Severity.High, "kernel.randomize_va_space",
                new Dictionary<string, string> { ["value"] = kp.RandomizeVaSpace?.ToString() ?? "missing" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-001", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-002: IP forwarding should be disabled unless this system is explicitly a router.
/// </summary>
public sealed class IpForwardingDisabledRule : IRule
{
    public string Id => "KERN-002";
    public string Category => "Kernel";
    public string Description => "IP forwarding should be disabled";
    public string WhatItChecks => "Checks whether IPv4 and IPv6 forwarding are disabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 3.1",
            ControlName = "Network Parameters (Host Only)",
            WhyItMatters = "IP forwarding allows the system to act as a router. On non-router hosts, this is unnecessary and can be abused for traffic redirection, lateral movement, and man-in-the-middle attacks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.1.1 — Ensure IP forwarding is disabled"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-002", Description, CisMappings, MitreTechniques);

        var ipv4Forward = kp.IpForwardIpv4.GetValueOrDefault(0);
        var ipv6Forward = kp.IpForwardIpv6.GetValueOrDefault(0);

        if (ipv4Forward != 0 || ipv6Forward != 0)
        {
            var issues = new List<string>();
            if (ipv4Forward != 0) issues.Add("IPv4 forwarding enabled");
            if (ipv6Forward != 0) issues.Add("IPv6 forwarding enabled");

            return RuleResult.Fail(Id, Category, "KERN-002", Description, Severity.High, "ip_forward",
                new Dictionary<string, string>
                {
                    ["ipv4"] = kp.IpForwardIpv4?.ToString() ?? "missing",
                    ["ipv6"] = kp.IpForwardIpv6?.ToString() ?? "missing",
                    ["issues"] = string.Join(", ", issues)
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-002", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-003: ICMP redirects should be disabled to prevent route hijacking.
/// </summary>
public sealed class IcmpRedirectsDisabledRule : IRule
{
    public string Id => "KERN-003";
    public string Category => "Kernel";
    public string Description => "ICMP redirects should be disabled";
    public string WhatItChecks => "Checks whether IPv4 and IPv6 ICMP redirect acceptance are disabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/net/ipv4/conf/all/accept_redirects", "/proc/sys/net/ipv6/conf/all/accept_redirects" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 3.1",
            ControlName = "Network Parameters (Host Only)",
            WhyItMatters = "ICMP redirects can be used by attackers to alter routing tables and redirect traffic through compromised hosts, enabling man-in-the-middle and traffic interception attacks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.1.2 — Ensure ICMP redirects are not accepted"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-003", Description, CisMappings, MitreTechniques);

        var ipv4Fail = kp.AcceptRedirectsIpv4 == 1;
        var ipv6Fail = kp.AcceptRedirectsIpv6 == 1;

        if (ipv4Fail || ipv6Fail)
        {
            return RuleResult.Fail(Id, Category, "KERN-003", Description, Severity.Medium, "accept_redirects",
                new Dictionary<string, string>
                {
                    ["ipv4"] = kp.AcceptRedirectsIpv4?.ToString() ?? "missing",
                    ["ipv6"] = kp.AcceptRedirectsIpv6?.ToString() ?? "missing"
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-003", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-004: Source routed packets should be disabled.
/// </summary>
public sealed class SourceRoutingDisabledRule : IRule
{
    public string Id => "KERN-004";
    public string Category => "Kernel";
    public string Description => "Source routed packets should be rejected";
    public string WhatItChecks => "Checks whether IPv4 source route acceptance is disabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/net/ipv4/conf/all/accept_source_route" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 3.1",
            ControlName = "Network Parameters (Host Only)",
            WhyItMatters = "Source routing allows senders to define the exact network path packets take. Attackers can use this to bypass security controls, probe internal networks, and circumvent routing policies.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.1.3 — Ensure source routed packets are not accepted"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-004", Description, CisMappings, MitreTechniques);

        if (kp.AcceptSourceRouteIpv4 == 1)
        {
            return RuleResult.Fail(Id, Category, "KERN-004", Description, Severity.Medium, "accept_source_route",
                new Dictionary<string, string> { ["value"] = kp.AcceptSourceRouteIpv4?.ToString() ?? "missing" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-004", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-005: Kernel module loading should be restricted.
/// </summary>
public sealed class KernelModuleLoadingRestrictedRule : IRule, IContextualRule
{
    public string Id => "KERN-005";
    public string Category => "Kernel";
    public string Description => "Kernel module loading should be restricted";
    public string WhatItChecks => "Checks whether kernel.modules_disabled is set to prevent loading new kernel modules";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/kernel/modules_disabled" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 1.4",
            ControlName = "Secure Boot Settings",
            WhyItMatters = "Unrestricted kernel module loading allows attackers to install rootkits, keyloggers, and other malicious kernel code. Restricting it hardens the system against kernel-level compromise.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.4.1 — Ensure loading and unloading of kernel modules is restricted"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
        => Evaluate(data, new RuleEvaluationContext(MachineRole.Workstation, null));

    public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-005", Description, CisMappings, MitreTechniques);

        var severity = context.Role == MachineRole.Server ? Severity.High : Severity.Medium;

        if (kp.ModulesDisabled.GetValueOrDefault(0) == 0)
        {
            return RuleResult.Fail(Id, Category, "KERN-005", Description, severity, "kernel.modules_disabled",
                new Dictionary<string, string> { ["value"] = kp.ModulesDisabled?.ToString() ?? "missing" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-005", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-006: Secure Boot should be enabled.
/// </summary>
public sealed class SecureBootEnabledRule : IRule
{
    public string Id => "KERN-006";
    public string Category => "Kernel";
    public string Description => "Secure Boot should be enabled";
    public string WhatItChecks => "Checks whether UEFI Secure Boot is enabled";
    public IReadOnlyList<string> SupportedDataSources => new[] { "mokutil --sb-state", "/sys/firmware/efi/efivars" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 1.4",
            ControlName = "Secure Boot Settings",
            WhyItMatters = "Secure Boot ensures only cryptographically signed bootloaders and kernels can execute, preventing rootkits and boot-time malware from compromising the system before the OS loads.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.4.2 — Ensure Secure Boot is enabled"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.SecureBootEnabled.HasValue)
        {
            return new RuleResult
            {
                RuleId = Id,
                Category = Category,
                Passed = true,
                Status = RuleStatus.NotApplicable,
                ExplanationKey = "KERN-006",
                Description = $"{Description} — Secure Boot not available on this system (BIOS/legacy system).",
                CisMappings = CisMappings,
                MitreTechniques = MitreTechniques
            };
        }

        if (!kp.SecureBootEnabled.Value)
        {
            return RuleResult.Fail(Id, Category, "KERN-006", Description, Severity.Medium, "SecureBoot",
                new Dictionary<string, string> { ["status"] = "disabled" }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-006", Description, CisMappings, MitreTechniques);
    }
}

/// <summary>
/// KERN-007: Kernel pointer and dmesg exposure should be restricted.
/// </summary>
public sealed class KernelPointerExposureRestrictedRule : IRule
{
    public string Id => "KERN-007";
    public string Category => "Kernel";
    public string Description => "Kernel pointer and dmesg exposure should be restricted";
    public string WhatItChecks => "Checks whether kptr_restrict and dmesg_restrict are enabled to prevent leaking kernel memory addresses";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 1.5",
            ControlName = "Additional Process Hardening",
            WhyItMatters = "Exposing kernel pointers through /proc and dmesg aids attackers in developing reliable kernel exploits. Restricting them increases the difficulty of privilege escalation attacks.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.5.3 — Ensure kernel pointer restriction is enabled"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KernelHardeningMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var kp = data.KernelParameters;
        if (kp == null || !kp.ParametersReadable)
            return RuleResult.Pass(Id, Category, "KERN-007", Description, CisMappings, MitreTechniques);

        var kptr = kp.KptrRestrict.GetValueOrDefault(0);
        var dmesg = kp.DmesgRestrict.GetValueOrDefault(0);

        if (kptr < 1 || dmesg == 0)
        {
            var issues = new List<string>();
            if (kptr < 1) issues.Add("kptr_restrict too low");
            if (dmesg == 0) issues.Add("dmesg_restrict disabled");

            return RuleResult.Fail(Id, Category, "KERN-007", Description, Severity.Medium, "kernel exposure",
                new Dictionary<string, string>
                {
                    ["kptr_restrict"] = kp.KptrRestrict?.ToString() ?? "missing",
                    ["dmesg_restrict"] = kp.DmesgRestrict?.ToString() ?? "missing",
                    ["issues"] = string.Join(", ", issues)
                }, CisMappings, MitreTechniques);
        }

        return RuleResult.Pass(Id, Category, "KERN-007", Description, CisMappings, MitreTechniques);
    }
}
