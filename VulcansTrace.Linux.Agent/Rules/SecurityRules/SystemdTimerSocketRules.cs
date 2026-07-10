using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules.SecurityRules;

internal static class SystemdMitreMappings
{
    public static readonly IReadOnlyList<MitreTechnique> Techniques = new[]
    {
        new MitreTechnique
        {
            TechniqueId = "T1543.002",
            TechniqueName = "Systemd Service",
            Tactic = "Persistence",
            WhyItMatters = "Systemd timers and sockets can be abused for persistence and lateral movement."
        },
        new MitreTechnique
        {
            TechniqueId = "T1021",
            TechniqueName = "Remote Services",
            Tactic = "Lateral Movement",
            WhyItMatters = "Socket-activated services exposed on public interfaces expand the remote attack surface."
        }
    };
}

/// <summary>
/// SYS-001: Systemd timers should not run more frequently than once per minute.
/// </summary>
public sealed class SystemdShortTimerIntervalRule : IRule
{
    public string Id => "SYS-001";
    public string Category => "Systemd";
    public string Description => "Systemd timers should not run more frequently than once per minute";
    public string WhatItChecks => "Checks whether any active timer has a sub-minute interval";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-timers", "systemctl list-units" };
    public Severity Severity => Severity.Medium;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Establish and Maintain a Secure Configuration Process",
            WhyItMatters = "Very frequent timers increase resource consumption and create opportunities for attackers to retry failed persistence attempts rapidly.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 2.2 — Configure timers securely"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SystemdMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SystemdTimerSocketConfig == null || !data.SystemdTimerSocketConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var shortTimers = data.SystemdTimerSocketConfig.Timers
            .Where(t => t.Active && SystemdTimerSocketScanner.IsShortInterval(t.Interval))
            .Select(t => t.Name)
            .ToList();

        if (shortTimers.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"Timers with sub-minute intervals: {string.Join(", ", shortTimers)}",
            new Dictionary<string, string> { ["timers"] = string.Join(",", shortTimers) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// SYS-002: Socket units should not listen on public interfaces.
/// </summary>
public sealed class SystemdPublicSocketRule : IRule
{
    public string Id => "SYS-002";
    public string Category => "Systemd";
    public string Description => "Systemd socket units should not listen on public interfaces";
    public string WhatItChecks => "Checks whether any socket listens on 0.0.0.0, ::, or a wildcard address";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-sockets", "systemctl list-units" };
    public Severity Severity => Severity.High;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
    {
        new CisBenchmarkMapping
        {
            ControlId = "CIS 4.1",
            ControlName = "Ensure sockets are not exposed publicly",
            WhyItMatters = "Socket units bound to public interfaces expose services to the network before any firewall or service-level access controls are evaluated.",
            BenchmarkReference = "CIS Ubuntu 24.04 LTS 4.1 — Bound network sockets"
        }
    };

    public IReadOnlyList<MitreTechnique> MitreTechniques => SystemdMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SystemdTimerSocketConfig == null || !data.SystemdTimerSocketConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var publicSockets = data.SystemdTimerSocketConfig.Sockets
            .Where(s => s.Listening && SystemdTimerSocketScanner.IsPublicListenAddress(s.ListenAddress))
            .Select(s => $"{s.Name} ({s.ListenAddress})")
            .ToList();

        if (publicSockets.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"Public sockets: {string.Join(", ", publicSockets)}",
            new Dictionary<string, string> { ["sockets"] = string.Join(";", publicSockets) },
            CisMappings, MitreTechniques);
    }
}

/// <summary>
/// SYS-003: Socket-activated services should not also be running as standalone services.
/// </summary>
public sealed class SystemdRedundantSocketServiceRule : IRule
{
    public string Id => "SYS-003";
    public string Category => "Systemd";
    public string Description => "Socket-activated services should not also run as standalone services";
    public string WhatItChecks => "Checks whether a service triggered by a socket is also running independently";
    public IReadOnlyList<string> SupportedDataSources => new[] { "systemctl list-sockets", "systemctl list-units" };
    // Reads RunningServices (produced by the Service scanner) to detect a socket-activated
    // service that is *also* running standalone. Declaring it keeps a targeted /systemd audit
    // from starving this rule of the Service scanner's data.
    public IReadOnlyCollection<string> RequiredDataFields => new[] { "RunningServices" };
    public Severity Severity => Severity.Low;

    public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
    public IReadOnlyList<MitreTechnique> MitreTechniques => SystemdMitreMappings.Techniques;

    public RuleResult Evaluate(ScanData data)
    {
        if (data.SystemdTimerSocketConfig == null || !data.SystemdTimerSocketConfig.ConfigReadable)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        var runningServices = new HashSet<string>(
            data.RunningServices.Select(s => s.Name),
            StringComparer.OrdinalIgnoreCase);

        var redundant = data.SystemdTimerSocketConfig.Sockets
            .Where(s => s.Listening &&
                        !string.IsNullOrWhiteSpace(s.TriggerUnit) &&
                        runningServices.Contains(s.TriggerUnit))
            .Select(s => $"{s.Name} -> {s.TriggerUnit}")
            .ToList();

        if (redundant.Count == 0)
            return RuleResult.Pass(Id, Category, Id, Description, CisMappings, MitreTechniques);

        return RuleResult.Fail(Id, Category, Id, Description, Severity,
            $"Redundant socket+service pairs: {string.Join(", ", redundant)}",
            new Dictionary<string, string> { ["pairs"] = string.Join(";", redundant) },
            CisMappings, MitreTechniques);
    }
}
