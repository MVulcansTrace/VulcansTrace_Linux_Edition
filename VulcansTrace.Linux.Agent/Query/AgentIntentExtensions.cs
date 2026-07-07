namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Intent classification helpers for the CLI and other callers that need to decide
/// whether to pre-run an audit before invoking <see cref="IAgent.AskAsync"/>.
/// </summary>
public static class AgentIntentExtensions
{
    /// <summary>
    /// Returns whether the intent is an audit-producing intent that <c>AskAsync</c>
    /// executes as a live scan (FullAudit, FirewallCheck, PortCheck, etc.).
    /// Used by the CLI to avoid running a redundant pre-audit for queries whose
    /// execution already performs the audit.
    /// </summary>
    public static bool IsAuditIntent(this AgentIntent intent) => intent switch
    {
        AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.NetworkCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.PortCheck
            or AgentIntent.SshCheck
            or AgentIntent.FilePermissionCheck
            or AgentIntent.FilesystemAuditCheck
            or AgentIntent.KernelCheck
            or AgentIntent.UserAccountCheck
            or AgentIntent.LoggingAuditCheck
            or AgentIntent.SudoersCheck
            or AgentIntent.SystemdTimerSocketCheck
            or AgentIntent.MacCheck
            or AgentIntent.BootloaderCheck
            or AgentIntent.CronJobCheck
            or AgentIntent.PackageVulnerabilityCheck
            or AgentIntent.ContainerCheck
            or AgentIntent.KubernetesCheck
            or AgentIntent.ThreatIntelCheck
            or AgentIntent.YaraCheck
            or AgentIntent.ProcessRuntimeCheck => true,
        _ => false
    };

    /// <summary>
    /// Returns whether the CLI should run an upfront audit for this intent.
    /// </summary>
    /// <param name="intent">The resolved intent for the user's query.</param>
    /// <param name="hasLastResult">True if the agent already has a persisted or in-memory audit result.</param>
    public static bool ShouldRunAuditBeforeAsk(this AgentIntent intent, bool hasLastResult)
    {
        return intent switch
        {
            // Explicit audit intents always need live scan data.
            AgentIntent.FullAudit
                or AgentIntent.FirewallCheck
                or AgentIntent.NetworkCheck
                or AgentIntent.ServiceCheck
                or AgentIntent.PortCheck
                or AgentIntent.SshCheck
                or AgentIntent.FilePermissionCheck
                or AgentIntent.FilesystemAuditCheck
                or AgentIntent.KernelCheck
                or AgentIntent.UserAccountCheck
                or AgentIntent.LoggingAuditCheck
                or AgentIntent.SudoersCheck
                or AgentIntent.SystemdTimerSocketCheck
                or AgentIntent.MacCheck
                or AgentIntent.BootloaderCheck
                or AgentIntent.CronJobCheck
                or AgentIntent.PackageVulnerabilityCheck
                or AgentIntent.ContainerCheck
                or AgentIntent.KubernetesCheck
                or AgentIntent.ThreatIntelCheck
                or AgentIntent.YaraCheck
                or AgentIntent.ProcessRuntimeCheck
                or AgentIntent.SetBaseline
                => true,

            // Context-dependent follow-ups need an audit only when there is no prior result to follow up on.
            AgentIntent.ExplainFinding
                or AgentIntent.ShowEvidence
                or AgentIntent.ShowChanges
                or AgentIntent.ExplainCritical
                or AgentIntent.FilterCategory
                or AgentIntent.PrioritizeRemediation
                or AgentIntent.FixFinding
                or AgentIntent.ListSuppressed
                or AgentIntent.RiskScore
                or AgentIntent.StartRemediation
                or AgentIntent.InvestigateRecurrence
                or AgentIntent.AnswerDiagnosticQuestion
                => !hasLastResult,

            // Remediation/conversational intents never need an upfront audit.
            // CheckDrift and VerifyRemediation run their own audits internally when required.
            _ => false
        };
    }
}
