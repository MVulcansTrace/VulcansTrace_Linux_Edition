using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Provides deterministic, context-aware response text.
/// Unlike an LLM, this only fills pre-defined templates with variables
/// from the conversation context.
/// </summary>
public sealed class ResponseTemplateProvider
{
    /// <summary>
    /// Builds a clarification prompt that uses conversation history.
    /// </summary>
    public string BuildClarificationPrompt(AgentQuery query, EntityFrame entities)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(entities);

        var intentNames = new[] { query.Intent }
            .Concat(query.AlternativeIntents ?? Array.Empty<AgentIntent>())
            .Distinct()
            .Select(GetIntentDisplayName)
            .ToList();

        if (intentNames.Count == 0)
        {
            return "I could read that a couple of ways. Please ask for a specific audit area, such as firewall, ports, SSH, services, network, or full audit.";
        }

        var contextHint = entities.LastTopic != ConversationTopic.Unknown
            ? $" You were asking about {GetTopicDisplayName(entities.LastTopic)}."
            : string.Empty;

        return $"I could read that a couple of ways: {string.Join(", ", intentNames)}.{contextHint} Please clarify so I run the right check.";
    }

    private static string GetIntentDisplayName(AgentIntent intent) => intent switch
    {
        AgentIntent.FullAudit => "full audit",
        AgentIntent.FirewallCheck => "firewall",
        AgentIntent.NetworkCheck => "network",
        AgentIntent.ServiceCheck => "services",
        AgentIntent.PortCheck => "ports",
        AgentIntent.SshCheck => "SSH",
        AgentIntent.FilePermissionCheck => "file permissions",
        AgentIntent.FilesystemAuditCheck => "filesystem audit",
        AgentIntent.KernelCheck => "kernel hardening",
        AgentIntent.UserAccountCheck => "user accounts",
        AgentIntent.LoggingAuditCheck => "logging",
        AgentIntent.CronJobCheck => "cron jobs",
        AgentIntent.PackageVulnerabilityCheck => "package vulnerabilities",
        AgentIntent.ContainerCheck => "containers",
        AgentIntent.KubernetesCheck => "kubernetes",
        AgentIntent.ThreatIntelCheck => "threat intel",
        AgentIntent.YaraCheck => "YARA scan",
        AgentIntent.ProcessRuntimeCheck => "process runtime",
        AgentIntent.ExplainFinding => "explain a finding",
        AgentIntent.ShowEvidence => "show evidence",
        AgentIntent.ShowChanges => "audit changes",
        AgentIntent.ExplainCritical => "critical finding explanation",
        AgentIntent.FilterCategory => "filter findings",
        AgentIntent.PrioritizeRemediation => "remediation priority",
        AgentIntent.FixFinding => "guided remediation",
        AgentIntent.ListSuppressed => "suppressed findings",
        AgentIntent.SetBaseline => "set baseline",
        AgentIntent.CheckDrift => "baseline drift",
        AgentIntent.ShowBaseline => "show baseline",
        AgentIntent.RiskScore => "risk score",
        AgentIntent.StartRemediation => "start remediation",
        AgentIntent.VerifyRemediation => "verify remediation",
        AgentIntent.ListRemediationSessions => "list remediation sessions",
        AgentIntent.ResumeRemediation => "resume remediation session",
        AgentIntent.AddSessionNote => "add session note",
        AgentIntent.AddStepNote => "add step note",
        AgentIntent.Help => "help",
        _ => intent.ToString()
    };

    private static string GetTopicDisplayName(ConversationTopic topic) => topic switch
    {
        ConversationTopic.Audit => "audit results",
        ConversationTopic.Explanation => "a finding explanation",
        ConversationTopic.Remediation => "remediation",
        ConversationTopic.Comparison => "audit comparison",
        ConversationTopic.Drift => "baseline drift",
        ConversationTopic.Help => "help",
        _ => "your request"
    };
}
