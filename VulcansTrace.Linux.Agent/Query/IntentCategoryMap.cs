namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Maps <see cref="AgentIntent"/> values to the canonical audit category string
/// used by rules and coverage tracking. This keeps the intent-to-category
/// relationship in a single place so the suggestion engine and narrative composer
/// stay consistent with <see cref="Rules.RuleEvaluationService"/>.
/// </summary>
public static class IntentCategoryMap
{
    /// <summary>
    /// Returns the canonical category for a targeted audit intent, or <c>null</c>
    /// for non-audit intents and <see cref="AgentIntent.FullAudit"/>.
    /// </summary>
    public static string? GetCategory(AgentIntent intent) => intent switch
    {
        AgentIntent.FirewallCheck => "Firewall",
        AgentIntent.NetworkCheck => "Network",
        AgentIntent.ServiceCheck => "Service",
        AgentIntent.PortCheck => "Port",
        AgentIntent.SshCheck => "SSH",
        AgentIntent.FilePermissionCheck => "FilePermission",
        AgentIntent.FilesystemAuditCheck => "FilesystemAudit",
        AgentIntent.KernelCheck => "Kernel",
        AgentIntent.UserAccountCheck => "UserAccount",
        AgentIntent.LoggingAuditCheck => "Logging",
        AgentIntent.CronJobCheck => "CronJob",
        AgentIntent.PackageVulnerabilityCheck => "PackageVulnerability",
        AgentIntent.ContainerCheck => "Container",
        AgentIntent.KubernetesCheck => "Kubernetes",
        AgentIntent.ThreatIntelCheck => "ThreatIntel",
        AgentIntent.YaraCheck => "Yara",
        AgentIntent.ProcessRuntimeCheck => "ProcessRuntime",
        _ => null
    };

    /// <summary>
    /// All targeted audit categories tracked for coverage.
    /// </summary>
    public static IReadOnlyList<string> AllCategories { get; } = new[]
    {
        "Firewall",
        "Network",
        "Service",
        "Port",
        "SSH",
        "FilePermission",
        "FilesystemAudit",
        "Kernel",
        "UserAccount",
        "Logging",
        "CronJob",
        "PackageVulnerability",
        "Container",
        "Kubernetes",
        "ThreatIntel",
        "Yara",
        "ProcessRuntime"
    };

    /// <summary>
    /// Returns <c>true</c> for the comprehensive audit intent that covers every category.
    /// </summary>
    public static bool IsFullAudit(AgentIntent intent) => intent == AgentIntent.FullAudit;

    /// <summary>
    /// Returns <c>true</c> if the intent is a targeted audit that maps to a single category.
    /// </summary>
    public static bool IsTargetedAudit(AgentIntent intent) => GetCategory(intent) != null;

    /// <summary>
    /// Returns <c>true</c> if the intent is any audit intent (full or targeted).
    /// </summary>
    public static bool IsAuditIntent(AgentIntent intent) => IsFullAudit(intent) || IsTargetedAudit(intent);

    /// <summary>
    /// Returns the targeted audit intent that maps to <paramref name="category"/>,
    /// or <c>null</c> if the category is unknown.
    /// </summary>
    public static AgentIntent? GetIntent(string category) => category switch
    {
        "Firewall" => AgentIntent.FirewallCheck,
        "Network" => AgentIntent.NetworkCheck,
        "Service" => AgentIntent.ServiceCheck,
        "Port" => AgentIntent.PortCheck,
        "SSH" => AgentIntent.SshCheck,
        "FilePermission" => AgentIntent.FilePermissionCheck,
        "FilesystemAudit" => AgentIntent.FilesystemAuditCheck,
        "Kernel" => AgentIntent.KernelCheck,
        "UserAccount" => AgentIntent.UserAccountCheck,
        "Logging" => AgentIntent.LoggingAuditCheck,
        "CronJob" => AgentIntent.CronJobCheck,
        "PackageVulnerability" => AgentIntent.PackageVulnerabilityCheck,
        "Container" => AgentIntent.ContainerCheck,
        "Kubernetes" => AgentIntent.KubernetesCheck,
        "ThreatIntel" => AgentIntent.ThreatIntelCheck,
        "Yara" => AgentIntent.YaraCheck,
        "ProcessRuntime" => AgentIntent.ProcessRuntimeCheck,
        _ => null
    };

    /// <summary>
    /// Returns a user-friendly chip label for a category suggestion.
    /// </summary>
    public static string GetSuggestionLabel(string category) => category switch
    {
        "FilePermission" => "Check file permissions",
        "FilesystemAudit" => "Check filesystem security",
        "Logging" => "Check logging audit",
        "PackageVulnerability" => "Check package vulnerabilities",
        "ProcessRuntime" => "Check running processes",
        "ThreatIntel" => "Check threat intel",
        "UserAccount" => "Check user accounts",
        _ => $"Check {category.ToLowerInvariant()}"
    };

    /// <summary>
    /// Returns a natural-language query that will map back to the category's audit intent.
    /// </summary>
    public static string GetSuggestionQuery(string category) => category switch
    {
        // "ssh"/"sshd" contain "ss" (a PortCheck keyword); use "ssh config" so the chip scores high
        // enough on SshCheck to resolve unambiguously instead of prompting SSH-vs-Port disambiguation.
        "SSH" => "check ssh config",
        "FilePermission" => "check file permissions",
        "FilesystemAudit" => "check filesystem security",
        "Logging" => "check logging audit",
        "PackageVulnerability" => "check package vulnerabilities",
        "ProcessRuntime" => "check running processes",
        "ThreatIntel" => "check threat intel",
        "UserAccount" => "check user accounts",
        _ => $"check {category.ToLowerInvariant()}"
    };
}
