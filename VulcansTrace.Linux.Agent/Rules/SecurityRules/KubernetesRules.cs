using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class KubernetesMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1610", TechniqueName = "Deploy Container", Tactic = "Execution", WhyItMatters = "Attackers may deploy malicious containers to execute code or evade defenses within the cluster." },
        new MitreTechnique { TechniqueId = "T1611", TechniqueName = "Escape to Host", Tactic = "Privilege Escalation", WhyItMatters = "Privileged pods and host namespace sharing allow container escape and host compromise." },
    };
}

/// <summary>
/// K8S-001: Kubernetes pods should not run privileged containers.
/// </summary>
public sealed class K8sPrivilegedPodRule : IRule
{
    public string Id => "K8S-001";
    public string Category => FindingCategories.Kubernetes;
    public string Description => "Kubernetes pods should not run privileged containers";
    public string WhatItChecks => "Checks whether any Kubernetes pod has a container running in privileged mode";
    public IReadOnlyList<string> SupportedDataSources => new[] { "kubectl" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2.1",
            ControlName = "Minimize Admission of Privileged Containers",
            WhyItMatters = "Privileged containers bypass all container security controls and have full host access. This is a scored item in CIS Kubernetes Benchmark.",
            BenchmarkReference = "CIS Kubernetes Benchmark 5.2.1 — Minimize the admission of privileged containers"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KubernetesMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var violatingPods = data.KubernetesPods
            .Where(p => p.Containers.Any(c => c.Privileged))
            .ToList();

        if (violatingPods.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", violatingPods.Select(p => $"{p.Namespace}/{p.Name}").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = violatingPods.Count.ToString(), ["pods"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// K8S-002: Kubernetes pods should not use hostNetwork, hostPID, or hostIPC.
/// </summary>
public sealed class K8sHostNamespaceRule : IRule
{
    public string Id => "K8S-002";
    public string Category => FindingCategories.Kubernetes;
    public string Description => "Kubernetes pods should not use hostNetwork, hostPID, or hostIPC";
    public string WhatItChecks => "Checks whether any Kubernetes pod shares host network, PID, or IPC namespaces";
    public IReadOnlyList<string> SupportedDataSources => new[] { "kubectl" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2.4",
            ControlName = "Minimize Admission of HostNetwork and HostPID",
            WhyItMatters = "Sharing host namespaces removes the isolation boundary between pod and host, allowing direct access to host network interfaces and processes.",
            BenchmarkReference = "CIS Kubernetes Benchmark 5.2.4 — Minimize the admission of containers wishing to share the host network namespace"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KubernetesMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var violatingPods = data.KubernetesPods
            .Where(p => p.HostNetwork || p.HostPid || p.HostIpc)
            .ToList();

        if (violatingPods.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", violatingPods.Select(p => $"{p.Namespace}/{p.Name}").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = violatingPods.Count.ToString(), ["pods"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// K8S-003: Kubernetes containers should run as non-root.
/// </summary>
public sealed class K8sRunAsRootRule : IRule
{
    public string Id => "K8S-003";
    public string Category => FindingCategories.Kubernetes;
    public string Description => "Kubernetes containers should run as non-root";
    public string WhatItChecks => "Checks whether any Kubernetes container may run as root (missing runAsNonRoot or runAsUser: 0)";
    public IReadOnlyList<string> SupportedDataSources => new[] { "kubectl" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2.6",
            ControlName = "Minimize Admission of Root Containers",
            WhyItMatters = "Running containers as root increases the blast radius of a compromise and makes container escape trivial if coupled with a kernel vulnerability.",
            BenchmarkReference = "CIS Kubernetes Benchmark 5.2.6 — Minimize the admission of root containers"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KubernetesMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var violatingPods = data.KubernetesPods
            .Where(p => p.Containers.Any(c => c.RunAsRoot))
            .ToList();

        if (violatingPods.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", violatingPods.Select(p => $"{p.Namespace}/{p.Name}").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = violatingPods.Count.ToString(), ["pods"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// K8S-004: Kubernetes containers should have hardened security contexts.
/// </summary>
public sealed class K8sSecurityContextRule : IRule
{
    public string Id => "K8S-004";
    public string Category => FindingCategories.Kubernetes;
    public string Description => "Kubernetes containers should have hardened security contexts";
    public string WhatItChecks => "Checks whether Kubernetes containers disable privilege escalation, enforce readOnlyRootFilesystem, drop ALL capabilities, and use a confined seccomp profile";
    public IReadOnlyList<string> SupportedDataSources => new[] { "kubectl" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 5.2.7",
            ControlName = "Enforce Security Context Constraints",
            WhyItMatters = "Missing security context fields (readOnlyRootFilesystem, dropped capabilities, seccomp) leave pods vulnerable to runtime exploits and privilege escalation.",
            BenchmarkReference = "CIS Kubernetes Benchmark 5.2.7 — Enforce hardened container security contexts"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => KubernetesMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var violatingPods = data.KubernetesPods
            .Where(p => p.Containers.Any(c =>
                c.AllowPrivilegeEscalation
                || !c.ReadOnlyRootFilesystem
                || !c.DropAllCapabilities
                || string.IsNullOrEmpty(c.SeccompProfile)
                || c.SeccompProfile.Equals("Unconfined", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (violatingPods.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", violatingPods.Select(p => $"{p.Namespace}/{p.Name}").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = violatingPods.Count.ToString(), ["pods"] = target },
            CisMappings, MitreTechniques);
    }
}
