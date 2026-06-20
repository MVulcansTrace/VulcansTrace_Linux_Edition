namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Centralizes rule-id prefix parsing and category-specific guidance.
/// </summary>
public static class RuleCategoryResolver
{
    /// <summary>
    /// Extracts the uppercase category prefix from a rule id (e.g., "FW-002" → "FW").
    /// Returns the original rule id uppercased if no dash is present.
    /// </summary>
    public static string ResolvePrefix(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
            return string.Empty;

        var prefix = ruleId.Split('-')[0];
        return prefix.ToUpperInvariant();
    }

    /// <summary>
    /// Returns remediation-wisdom guidance for a rule based on its category prefix.
    /// </summary>
    public static string GetGuidance(string ruleId)
    {
        var category = ResolvePrefix(ruleId);

        return category switch
        {
            "SSH" => "A one-time fix won't hold here. You likely have a config-management tool (Ansible, cloud-init) or a system update re-applying the insecure SSH setting. Check your playbooks and image templates.",
            "FW" => "The firewall keeps reverting. Look for a startup script, network manager, or container orchestration layer that reconfigures rules after boot.",
            "USER" => "Privileged account settings keep returning. Check identity-management tools, cloud-init user-data, or account provisioning scripts that reapply UID or login-policy changes.",
            "KERN" => "Kernel settings are being reset at boot. Ensure sysctl values are persisted in /etc/sysctl.conf or /etc/sysctl.d/ and that initramfs is regenerated.",
            _ => "This finding has been fixed and returned repeatedly. Look for an automated process, config-management tool, or base image that re-applies the insecure setting."
        };
    }

    /// <summary>
    /// Returns concise guidance for a finding that just returned after a verified fix.
    /// </summary>
    public static string GetRegressionGuidance(string ruleId)
    {
        var category = ResolvePrefix(ruleId);

        return category switch
        {
            "SSH" => "Check SSH configuration management, cloud-init, package updates, or image templates that may have restored the insecure daemon setting.",
            "FW" => "Check firewall startup scripts, network-manager hooks, container orchestration, or reboot-time rule loaders that may have rebuilt the policy.",
            "USER" => "Check identity-management tools, cloud-init user-data, or account provisioning scripts that may have restored the account setting.",
            "KERN" => "Check sysctl drop-ins, boot-time hardening scripts, or image defaults that may have reset the kernel setting.",
            _ => "Check for automation, reboot-time defaults, configuration management, or base-image drift that may have restored the finding."
        };
    }
}
