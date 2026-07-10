using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class MacMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique
        {
            TechniqueId = "T1562.001",
            TechniqueName = "Impair Defenses: Disable or Modify Tools",
            Tactic = "Defense Evasion",
            WhyItMatters = "Disabled or permissive MAC frameworks remove a layer of access control that limits exploit blast radius."
        },
        new MitreTechnique
        {
            TechniqueId = "T1548",
            TechniqueName = "Abuse Elevation Control Mechanism",
            Tactic = "Privilege Escalation",
            WhyItMatters = "MAC frameworks enforce authorization boundaries; without them, privilege escalation paths are harder to contain."
        }
    };
}

/// <summary>
/// MAC-001: A mandatory access control framework should be active.
/// </summary>
public sealed class MacFrameworkActiveRule : IRule
{
    public string Id => "MAC-001";
    public string Category => "Mac";
    public string Description => "A mandatory access control framework (AppArmor or SELinux) should be active";
    public string WhatItChecks => "Checks whether AppArmor or SELinux is installed and enforcing";
    public IReadOnlyList<string> SupportedDataSources => new[] { "aa-status", "getenforce", "/sys/module/apparmor", "/sys/fs/selinux" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Operating without AppArmor or SELinux removes kernel-level mandatory access controls that constrain process privileges and limit exploit impact.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.6 — Ensure mandatory access control is enabled"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => MacMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.MacConfig == null || !data.MacConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var appArmorActive = data.MacConfig.AppArmorInstalled && data.MacConfig.AppArmorEnforcing;
        var selinuxActive = data.MacConfig.SelinuxInstalled && data.MacConfig.SelinuxMode == "enforcing";

        if (appArmorActive || selinuxActive)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"AppArmor installed={data.MacConfig.AppArmorInstalled}, enforcing={data.MacConfig.AppArmorEnforcing}; SELinux installed={data.MacConfig.SelinuxInstalled}, mode={data.MacConfig.SelinuxMode}",
            new Dictionary<string, string>
            {
                ["apparmorInstalled"] = data.MacConfig.AppArmorInstalled.ToString(),
                ["apparmorEnforcing"] = data.MacConfig.AppArmorEnforcing.ToString(),
                ["selinuxInstalled"] = data.MacConfig.SelinuxInstalled.ToString(),
                ["selinuxMode"] = data.MacConfig.SelinuxMode
            },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// MAC-002: AppArmor should not have unconfined processes.
/// </summary>
public sealed class MacAppArmorUnconfinedRule : IRule
{
    public string Id => "MAC-002";
    public string Category => "Mac";
    public string Description => "AppArmor should not have unconfined processes";
    public string WhatItChecks => "Checks whether aa-status reports unconfined processes";
    public IReadOnlyList<string> SupportedDataSources => new[] { "aa-status" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Unconfined processes bypass AppArmor restrictions, creating exceptions that attackers can exploit to move laterally or escalate privileges.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 1.6.1 — Ensure AppArmor is installed and enforcing"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => MacMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.MacConfig == null || !data.MacConfig.ConfigReadable || !data.MacConfig.AppArmorInstalled)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (data.MacConfig.AppArmorUnconfined.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"{data.MacConfig.AppArmorUnconfined.Count} unconfined AppArmor process/profile entries",
            new Dictionary<string, string> { ["unconfined"] = string.Join(",", data.MacConfig.AppArmorUnconfined.Take(10)) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// MAC-003: SELinux should be enforcing when installed.
/// </summary>
public sealed class MacSelinuxEnforcingRule : IRule
{
    public string Id => "MAC-003";
    public string Category => "Mac";
    public string Description => "SELinux should be enforcing when installed";
    public string WhatItChecks => "Checks whether SELinux is installed and set to enforcing mode";
    public IReadOnlyList<string> SupportedDataSources => new[] { "getenforce", "/etc/selinux/config" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "SELinux in permissive or disabled mode logs but does not block policy violations, leaving systems exposed to privilege escalation and lateral movement.",
            BenchmarkReference = "CIS Red Hat Enterprise Linux 8 1.6.1 — Ensure SELinux is enforcing"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => MacMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.MacConfig == null || !data.MacConfig.ConfigReadable || !data.MacConfig.SelinuxInstalled)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        if (data.MacConfig.SelinuxMode == "enforcing")
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"SELinux mode is {data.MacConfig.SelinuxMode}",
            new Dictionary<string, string> { ["mode"] = data.MacConfig.SelinuxMode },
            CisMappings, MitreTechniques);
    }
}
