using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class ContainerMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique { TechniqueId = "T1610", TechniqueName = "Deploy Container", Tactic = "Execution", WhyItMatters = "Attackers may deploy malicious containers to execute code or evade defenses within the cluster." },
        new MitreTechnique { TechniqueId = "T1611", TechniqueName = "Escape to Host", Tactic = "Privilege Escalation", WhyItMatters = "Privileged containers and host namespace sharing allow attackers to break out of container isolation." },
    };
}

/// <summary>
/// CTR-001: Privileged containers should not be running.
/// </summary>
public sealed class PrivilegedContainerRule : IRule
{
    public string Id => "CTR-001";
    public string Category => FindingCategories.Container;
    public string Description => "Privileged containers should not be running";
    public string WhatItChecks => "Checks whether any running container is configured with privileged mode";
    public IReadOnlyList<string> SupportedDataSources => new[] { "docker ps", "docker inspect", "crictl" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Privileged containers have full access to host resources, effectively bypassing container isolation. This is a scored item in CIS Docker Benchmark.",
            BenchmarkReference = "CIS Docker Benchmark 5.4 — Ensure that privileged containers are not used"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => ContainerMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var privileged = data.Containers.Where(c => c.IsPrivileged).ToList();
        if (privileged.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", privileged.Select(c => $"{c.Name} ({c.Image}:{c.Tag})").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = privileged.Count.ToString(), ["containers"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// CTR-002: Container images should not use the 'latest' tag.
/// </summary>
public sealed class LatestTagRule : IRule
{
    public string Id => "CTR-002";
    public string Category => FindingCategories.Container;
    public string Description => "Container images should not use the 'latest' tag";
    public string WhatItChecks => "Checks whether any running container image uses the 'latest' tag or no explicit tag";
    public IReadOnlyList<string> SupportedDataSources => new[] { "docker ps", "crictl" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Ensure Image Pinning Is Used",
            WhyItMatters = "The 'latest' tag is mutable and non-deterministic. It prevents reproducible deployments and makes rollback impossible.",
            BenchmarkReference = "CIS Docker Benchmark 4.1 — Ensure that a fixed tag or digest is used for base images"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => ContainerMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var latest = data.Containers
            .Where(c => c.Tag.Equals("latest", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(c.Tag))
            .ToList();
        if (latest.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", latest.Select(c => $"{c.Name} ({c.Image}:{c.Tag})").Take(5));
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = latest.Count.ToString(), ["containers"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// CTR-003: The Docker socket should not be exposed or mounted into containers.
/// </summary>
public sealed class DockerSocketExposedRule : IRule
{
    public string Id => "CTR-003";
    public string Category => FindingCategories.Container;
    public string Description => "The Docker socket should not be exposed or mounted into containers";
    public string WhatItChecks => "Checks whether /var/run/docker.sock exists on the host or is mounted into a running container";
    public IReadOnlyList<string> SupportedDataSources => new[] { "docker.sock", "docker inspect" };
    public Severity Severity => Severity.Critical;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Mounting the Docker socket gives a container full root-equivalent access to the host. This is one of the most dangerous container misconfigurations.",
            BenchmarkReference = "CIS Docker Benchmark 5.25 — Ensure that the Docker socket is not mounted inside any containers"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => ContainerMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var mountedContainers = data.Containers.Where(c => c.HasDockerSocketMount).ToList();
        var hostSocketExposed = data.ContainerRuntime?.DockerSocketExposed == true;

        if (mountedContainers.Count == 0 && !hostSocketExposed)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var details = new List<string>();
        if (hostSocketExposed)
            details.Add("/var/run/docker.sock exists on host");
        if (mountedContainers.Count > 0)
            details.Add($"mounted in: {string.Join(", ", mountedContainers.Select(c => c.Name).Take(5))}");

        var target = string.Join("; ", details);
        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["detail"] = target, ["count"] = mountedContainers.Count.ToString() },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// CTR-004: Container images should not be based on known risky base layers.
/// </summary>
public sealed class KnownBadBaseLayerRule : IRule
{
    public string Id => "CTR-005";
    public string Category => FindingCategories.Container;
    public string Description => "Container images should not use known risky base layers";
    public string WhatItChecks => "Checks local image references and base-image labels for known end-of-life base image signatures";
    public IReadOnlyList<string> SupportedDataSources => new[] { "docker ps", "docker inspect", "crictl" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Ensure Image Pinning Is Used",
            WhyItMatters = "End-of-life base images no longer receive security fixes, so derived containers inherit known vulnerable packages even when the application layer is current.",
            BenchmarkReference = "CIS Docker Benchmark 4.1 — Ensure that a fixed and maintained image base is used"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => ContainerMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        var risky = data.Containers
            .Where(c => c.KnownBadBaseLayers.Count > 0)
            .ToList();

        if (risky.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var target = string.Join(", ", risky
            .Select(c => $"{c.Name} ({string.Join("; ", c.KnownBadBaseLayers)})")
            .Take(5));

        return RuleResult.Fail(Id, Category, Id, Description, Severity, target,
            new Dictionary<string, string> { ["count"] = risky.Count.ToString(), ["containers"] = target },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// CTR-004: Containerd should use explicit namespaces rather than only the default.
/// </summary>
public sealed class ContainerdWeakDefaultsRule : IRule
{
    public string Id => "CTR-004";
    public string Category => FindingCategories.Container;
    public string Description => "Containerd should use explicit namespaces rather than only the default";
    public string WhatItChecks => "Checks whether containerd is available with only the default namespace and no explicit isolation";
    public IReadOnlyList<string> SupportedDataSources => new[] { "ctr namespace" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Using only the default namespace in containerd reduces workload isolation and complicates RBAC and resource governance.",
            BenchmarkReference = "CIS Containerd Benchmark 1.1 — Use explicit namespaces for workload isolation"
        }
    };
    public IReadOnlyList<MitreTechnique> MitreTechniques => ContainerMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.ContainerRuntime?.ContainerdAvailable != true)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var hasDefaultOnly = data.Warnings.Any(w => w.Contains("Containerd default namespace", StringComparison.OrdinalIgnoreCase));
        if (!hasDefaultOnly)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity, "containerd default namespace only",
            new Dictionary<string, string> { ["detail"] = "containerd is using only the default namespace without explicit isolation" },
            CisMappings, MitreTechniques);
    }
}
