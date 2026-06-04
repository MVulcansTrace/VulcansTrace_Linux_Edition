using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Composes user-facing result summaries and scanner capability reports.
/// </summary>
internal sealed class AgentResultComposer
{
    public string BuildSummary(
        AgentIntent intent,
        IReadOnlyList<Finding> findings,
        AnalysisResult? logResult,
        IReadOnlyList<RuleResult> allResults,
        int suppressedCount = 0,
        int crashedCount = 0)
    {
        var passedCount = allResults.Count(r => r.Status == RuleStatus.Passed);
        var failedCount = findings.Count;
        var highCritical = findings.Count(f => f.Severity >= Severity.High);
        var logFindingsCount = logResult?.Findings.Count ?? 0;

        var intentLabel = intent switch
        {
            AgentIntent.FullAudit => "Full audit",
            AgentIntent.FirewallCheck => "Firewall check",
            AgentIntent.NetworkCheck => "Network check",
            AgentIntent.ServiceCheck => "Service check",
            AgentIntent.PortCheck => "Port check",
            AgentIntent.SshCheck => "SSH check",
            AgentIntent.FilePermissionCheck => "File permission check",
            AgentIntent.FilesystemAuditCheck => "Filesystem audit check",
            AgentIntent.KernelCheck => "Kernel check",
            AgentIntent.UserAccountCheck => "User account check",
            AgentIntent.LoggingAuditCheck => "Logging audit check",
            AgentIntent.CronJobCheck => "Cron job check",
            AgentIntent.PackageVulnerabilityCheck => "Package vulnerability check",
            AgentIntent.ContainerCheck => "Container check",
            AgentIntent.KubernetesCheck => "Kubernetes check",
            AgentIntent.ExplainFinding => "Finding explanation",
            AgentIntent.FixFinding => "Interactive remediation",
            _ => "Audit"
        };

        var parts = new List<string> { $"{intentLabel} complete." };

        if (failedCount == 0 && suppressedCount == 0 && crashedCount == 0)
        {
            parts.Add($"All {passedCount} checks passed.");
        }
        else if (failedCount == 0)
        {
            parts.Add(suppressedCount > 0
                ? $"0 active issue(s), {suppressedCount} suppressed."
                : "0 active issue(s).");
            if (passedCount > 0)
            {
                parts.Add($"{passedCount} check(s) passed.");
            }
        }
        else
        {
            parts.Add($"{failedCount} issue(s) found, {highCritical} High/Critical.");
            if (passedCount > 0)
            {
                parts.Add($"{passedCount} check(s) passed.");
            }
        }

        if (failedCount > 0 && suppressedCount > 0)
        {
            parts.Add($"{suppressedCount} suppressed.");
        }

        if (crashedCount > 0)
        {
            parts.Add($"{crashedCount} rule(s) crashed.");
        }

        var notApplicableCount = allResults.Count(r => r.Status == RuleStatus.NotApplicable);
        if (notApplicableCount > 0)
        {
            parts.Add($"{notApplicableCount} check(s) not applicable.");
        }

        if (logFindingsCount > 0)
        {
            parts.Add($"Log analysis found {logFindingsCount} additional finding(s).");
        }

        return string.Join(" ", parts);
    }

    public string BuildCapabilityReport(IReadOnlyList<DataSourceCapability> capabilities)
    {
        if (capabilities.Count == 0)
            return string.Empty;

        var sourceOrder = new[]
        {
            "iptables",
            "nftables",
            "ss",
            "netstat",
            "ip addr",
            "ip route",
            "ss connections",
            "systemctl",
            "systemctl logging services",
            "auditd rules",
            "logrotate",
            "log forwarding",
            "sshd -T",
            "sshd_config",
            "stat"
        };

        var orderedCapabilities = capabilities
            .Where(cap => !string.IsNullOrWhiteSpace(cap.SourceName))
            .GroupBy(cap => cap.SourceName, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(cap => GetCapabilityPriority(cap.Status)).First())
            .OrderBy(cap =>
            {
                var index = Array.FindIndex(sourceOrder, source => source.Equals(cap.SourceName, StringComparison.OrdinalIgnoreCase));
                return index >= 0 ? index : int.MaxValue;
            })
            .ThenBy(cap => cap.SourceName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (orderedCapabilities.Count == 0)
            return string.Empty;

        var parts = new List<string>(orderedCapabilities.Count);
        foreach (var cap in orderedCapabilities)
        {
            var statusLabel = cap.Status switch
            {
                CapabilityStatus.Available => "available",
                CapabilityStatus.Unavailable => "unavailable",
                CapabilityStatus.PermissionLimited => "permission-limited",
                _ => "unknown"
            };
            var detail = string.Empty;
            if (!string.IsNullOrWhiteSpace(cap.Detail) && cap.Status != CapabilityStatus.Available)
            {
                var sanitized = cap.Detail.Trim().Replace('\n', ' ').Replace('\r', ' ');
                if (sanitized.Length > 80)
                    sanitized = sanitized.Substring(0, 77) + "...";
                detail = $" ({sanitized})";
            }
            parts.Add($"{cap.SourceName} {statusLabel}{detail}");
        }

        return "Data sources: " + string.Join("; ", parts) + ".";
    }

    private static int GetCapabilityPriority(CapabilityStatus status) => status switch
    {
        CapabilityStatus.PermissionLimited => 3,
        CapabilityStatus.Available => 2,
        CapabilityStatus.Unavailable => 1,
        _ => 0
    };
}
