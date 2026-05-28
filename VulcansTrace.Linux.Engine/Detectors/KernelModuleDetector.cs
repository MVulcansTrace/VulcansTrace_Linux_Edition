using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Parsing;

namespace VulcansTrace.Linux.Engine.Detectors;

/// <summary>
/// Identifies the use of specific iptables/nftables extensions and kernel modules.
/// </summary>
/// <remarks>
/// This detector analyzes log patterns to identify the use of advanced firewall features:
/// - Connection tracking (conntrack) extensions
/// - Rate limiting modules
/// - IPv6 extensions
/// - Connection state tracking
/// - Layer 7 filtering indicators
/// This information helps understand the security posture and sophistication of the firewall configuration.
/// </remarks>
public sealed class KernelModuleDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
    {
        if (!profile.EnableKernelModule || events.Count == 0)
            return DetectionResult.Empty;

        var findings = new List<Core.Finding>();
        var moduleTimestamps = new Dictionary<string, List<DateTime>>();

        void RecordModule(string moduleName, DateTime timestamp)
        {
            if (!moduleTimestamps.TryGetValue(moduleName, out var list))
            {
                list = new List<DateTime>();
                moduleTimestamps[moduleName] = list;
            }
            list.Add(timestamp);
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var rawLine = evt.RawLine ?? "";

            if (FirewallLogRegex.IsWholeToken(rawLine, "conntrack")
                || FirewallLogRegex.IsWholeToken(rawLine, "CT"))
            {
                RecordModule("Connection Tracking (conntrack)", evt.Timestamp);
            }

            if (FirewallLogRegex.IsWholeToken(rawLine, "limit")
                || FirewallLogRegex.IsWholeToken(rawLine, "rate"))
            {
                RecordModule("Rate Limiting", evt.Timestamp);
            }

            if (evt.SourceIP.Contains(":") || evt.DestinationIP.Contains(":"))
            {
                RecordModule("IPv6 Support", evt.Timestamp);
            }

            if (FirewallLogRegex.IsWholeToken(rawLine, "layer7")
                || FirewallLogRegex.IsWholeToken(rawLine, "l7"))
            {
                RecordModule("Layer 7 Filtering", evt.Timestamp);
            }

            if (FirewallLogRegex.IsWholeToken(rawLine, "quota")
                || FirewallLogRegex.IsWholeToken(rawLine, "hashlimit"))
            {
                RecordModule("Quota/Bandwidth Limiting", evt.Timestamp);
            }
        }

        var minEvents = profile.KernelModuleMinEvents > 0 ? profile.KernelModuleMinEvents : 1;

        foreach (var (module, timestamps) in moduleTimestamps)
        {
            if (timestamps.Count < minEvents)
                continue;

            findings.Add(new Core.Finding
            {
                Category = FindingCategories.KernelModule,
                Severity = Core.Severity.Info,
                SourceHost = "Firewall Configuration",
                Target = module,
                TimeRangeStart = timestamps.Min(),
                TimeRangeEnd = timestamps.Max(),
                ShortDescription = $"Detected {module}",
                Details = $"Analysis of firewall logs indicates the use of {module}. This provides insight into the firewall's security posture and capabilities."
            });
        }

        return new DetectionResult(findings);
    }
}