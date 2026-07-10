using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class BootloaderMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique
        {
            TechniqueId = "T1542.001",
            TechniqueName = "Bootkit",
            Tactic = "Persistence",
            WhyItMatters = "Unsigned or tampered boot loaders can subvert the OS before security controls start."
        },
        new MitreTechnique
        {
            TechniqueId = "T1014",
            TechniqueName = "Rootkit",
            Tactic = "Defense Evasion",
            WhyItMatters = "Kernel parameters such as nomodeset or init=/bin/bash can be abused to load rootkit-like components at boot."
        }
    };
}

/// <summary>
/// BOOT-001: Secure Boot should be enabled when UEFI is available.
/// </summary>
public sealed class BootloaderSecureBootEnabledRule : IRule
{
    public string Id => "BOOT-001";
    public string Category => "Bootloader";
    public string Description => "Secure Boot should be enabled when UEFI is available";
    public string WhatItChecks => "Checks whether Secure Boot is enabled via mokutil or EFI variables";
    public IReadOnlyList<string> SupportedDataSources => new[] { "mokutil", "/sys/firmware/efi/efivars" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Secure Boot prevents unauthorized boot loaders, kernels, and option ROMs from loading, reducing bootkit and rootkit risk.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.8 — Ensure Secure Boot is enabled"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => BootloaderMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.BootloaderConfig == null || !data.BootloaderConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!data.BootloaderConfig.SecureBootEnabled.HasValue)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (data.BootloaderConfig.SecureBootEnabled.Value)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            "Secure Boot is disabled",
            new Dictionary<string, string> { ["secureBoot"] = "disabled" },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// BOOT-002: Kernel command line should not contain single-user / rescue boot options.
/// </summary>
public sealed class NoRescueBootParameterRule : IRule
{
    public string Id => "BOOT-002";
    public string Category => "Bootloader";
    public string Description => "Kernel command line should not contain single-user or rescue boot parameters";
    public string WhatItChecks => "Checks whether /proc/cmdline contains systemd.debug-shell, init=/bin/bash, single, or rd.break";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/cmdline" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Rescue or debug-shell kernel parameters allow an attacker with physical or console access to bypass authentication and gain root without credentials.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.9 — Ensure bootloader password is set"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => BootloaderMitreMappings.Techniques;

    private static readonly string[] RescueParameters =
    {
        "single",
        "s",
        "init=/bin/bash",
        "init=/bin/sh",
        "rd.break",
        "systemd.debug-shell"
    };

    public RuleResult Evaluate(ScanData data)
    {
        if (data.BootloaderConfig == null || !data.BootloaderConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var cmdline = data.BootloaderConfig.KernelCmdline;
        if (string.IsNullOrWhiteSpace(cmdline))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var found = RescueParameters
            .Where(p => BootloaderScanner.CmdlineContains(cmdline, p))
            .ToList();

        if (found.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"Rescue/debug kernel parameters found: {string.Join(", ", found)}",
            new Dictionary<string, string> { ["parameters"] = string.Join(",", found) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// BOOT-003: GRUB should have a boot loader password set.
/// </summary>
public sealed class GrubPasswordSetRule : IRule
{
    public string Id => "BOOT-003";
    public string Category => "Bootloader";
    public string Description => "GRUB should have a boot loader password set";
    public string WhatItChecks => "Checks whether /etc/default/grub or /etc/grub.d references GRUB_PASSWORD or a superuser configuration";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/etc/default/grub", "/etc/grub.d" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Without a boot loader password, an attacker with physical access can edit kernel parameters at boot to bypass authentication and escalate privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.9 — Ensure boot loader password is set"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => BootloaderMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.BootloaderConfig == null || !data.BootloaderConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (!data.BootloaderConfig.GrubFileExists)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (data.BootloaderConfig.GrubPasswordConfigured ||
            BootloaderScanner.HasPasswordConfiguration(data.BootloaderConfig.GrubVariables))
        {
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);
        }

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            "No GRUB password or superuser configuration detected",
            new Dictionary<string, string> { ["grubFile"] = "/etc/default/grub" },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// BOOT-004: Kernel module loading should be restricted via kernel command line.
/// </summary>
public sealed class KernelModuleLoadRestrictionRule : IRule
{
    public string Id => "BOOT-004";
    public string Category => "Bootloader";
    public string Description => "Kernel module loading should be restricted via kernel command line";
    public string WhatItChecks => "Checks whether /proc/cmdline contains modules_disabled or module.sig_enforce";
    public IReadOnlyList<string> SupportedDataSources => new[] { "/proc/cmdline" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Allowing unsigned or arbitrary kernel modules to load after boot exposes the system to rootkit-style persistence. Boot-time module restrictions close this gap.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.6.4 — Ensure kernel module loading is disabled"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => BootloaderMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.BootloaderConfig == null || !data.BootloaderConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var cmdline = data.BootloaderConfig.KernelCmdline;
        if (string.IsNullOrWhiteSpace(cmdline))
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var hasModulesDisabled = IsEnabledKernelSwitch(cmdline, "modules_disabled") ||
                                 IsEnabledKernelSwitch(cmdline, "module.sig_enforce");

        if (hasModulesDisabled)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            "No kernel command-line module restriction (modules_disabled or module.sig_enforce) detected",
            new Dictionary<string, string> { ["cmdline"] = cmdline },
            CisMappings, MitreTechniques);
    }

    private static bool IsEnabledKernelSwitch(string cmdline, string parameter)
    {
        var value = BootloaderScanner.CmdlineParameterValue(cmdline, parameter);
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("on", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("y", StringComparison.OrdinalIgnoreCase);
    }
}
