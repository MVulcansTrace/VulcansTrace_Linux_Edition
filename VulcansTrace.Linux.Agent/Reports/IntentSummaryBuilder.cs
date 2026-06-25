using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds the friendly "I ran a … &lt;tool&gt; is missing" lead sentence shown when an audit's
/// primary tool is unavailable. The denser count summary for ordinary results is produced by
/// <see cref="AgentResultComposer"/>; this builder covers only the missing-tool case, which the
/// composer has no concept of (it never sees interpreted warnings).
/// </summary>
public sealed class IntentSummaryBuilder
{
    /// <summary>
    /// Builds a lead that opens with the missing-tool explanation, then summarizes any findings
    /// and passed checks that still resulted.
    /// </summary>
    /// <param name="intent">The audit intent that was run.</param>
    /// <param name="findings">Findings the audit produced despite the missing tool.</param>
    /// <param name="passedCount">How many checks passed.</param>
    /// <param name="missingTool">The interpreted missing-tool warning to lead with.</param>
    public string BuildMissingToolLead(
        AgentIntent intent,
        IReadOnlyList<Finding> findings,
        int passedCount,
        UserFriendlyWarning missingTool)
    {
        var intentLabel = GetIntentLabel(intent);
        var findingCount = findings.Count;
        var highCritical = findings.Count(f => f.Severity >= Severity.High);

        var lead = $"I ran a {intentLabel.ToLowerInvariant()}. {missingTool.Message}";
        if (findingCount > 0)
        {
            var issueNoun = findingCount == 1 ? "issue" : "issues";
            lead += $" Still, I found {findingCount} {issueNoun}, {highCritical} High/Critical.";
            if (passedCount > 0)
            {
                var checkNoun = passedCount == 1 ? "check" : "checks";
                lead += $" {passedCount} other {checkNoun} passed.";
            }
        }
        else if (passedCount > 0)
        {
            var checkNoun = passedCount == 1 ? "check" : "checks";
            lead += $" {passedCount} other {checkNoun} passed.";
        }
        return lead;
    }

    private static string GetIntentLabel(AgentIntent intent) => intent switch
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
        AgentIntent.ThreatIntelCheck => "Threat intel check",
        AgentIntent.YaraCheck => "YARA scan",
        AgentIntent.ProcessRuntimeCheck => "Process runtime check",
        _ => "Audit"
    };
}
