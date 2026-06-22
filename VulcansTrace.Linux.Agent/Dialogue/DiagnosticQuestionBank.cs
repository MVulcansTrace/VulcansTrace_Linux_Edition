using VulcansTrace.Linux.Agent.Memory;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Deterministic, category-keyed bank of diagnostic questions for recurring findings.
/// </summary>
public sealed class DiagnosticQuestionBank
{
    /// <summary>
    /// Returns a diagnostic question for a recurring finding based on its category and memory profile.
    /// </summary>
    public string? GetQuestion(string category, RuleStatusTrend trend, int closedCycleCount)
    {
        if (closedCycleCount < 2 && trend != RuleStatusTrend.Worsening)
            return null;

        var normalizedCategory = category.ToUpperInvariant();

        if (trend == RuleStatusTrend.Worsening)
        {
            return normalizedCategory switch
            {
                "FW" or "FIREWALL" or "IPTABLES" or "NFTABLES" =>
                    "Your firewall rules are getting worse over time. Did you recently run a system update or reboot?",
                "SSH" or "SSHD" =>
                    "Your SSH hardening is getting worse over time. Did you recently run a system update or reboot?",
                "KERN" or "KERNEL" =>
                    "Your kernel hardening is getting worse over time. Did you recently run a system update or reboot?",
                _ => $"Your {category} findings are getting worse over time. Did you recently run a system update or reboot?"
            };
        }

        return normalizedCategory switch
        {
            "FW" or "FIREWALL" or "IPTABLES" or "NFTABLES" =>
                "Are you running a config-management tool like Ansible, Puppet, or cloud-init that might be reverting your firewall rules?",
            "SSH" or "SSHD" =>
                "SSH settings are reverting. Are you using a cloud image template or config-management tool that reapplies sshd_config on reboot?",
            "KERN" or "KERNEL" =>
                "Kernel parameters keep changing back. Do you have sysctl drop-in files under /etc/sysctl.d/ that might override your changes?",
            "USER" or "USERACCOUNT" or "ACCOUNT" =>
                "Privileged account settings keep returning. Are you using an identity-management tool, cloud-init user-data, or account provisioning script that reapplies the setting?",
            _ => $"This {category} finding has been fixed and returned repeatedly. Are you using a config-management tool, base image, or startup script that re-applies the insecure setting?"
        };
    }
}
