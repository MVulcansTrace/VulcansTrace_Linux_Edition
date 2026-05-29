using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Classifies shell commands by their likely safety impact using keyword heuristics.
/// </summary>
public static class CommandSafetyClassifier
{
    // Destructive commands — highest priority
    private static readonly Regex DestructivePattern = new(
        @"\b(rm\s+-[rfR]\S*|mkfs\S*|dd\s+if=\S*|iptables\s+-F\b|nft\s+flush\b|nft\s+delete\b|ufw\s+reset\b|sysctl\s+--system\s+.*-p|>\s*/dev/sd[a-z]|parted\s+.*mklabel)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Package management
    private static readonly Regex PackagePattern = new(
        @"\b(apt\s+(install|remove|purge|autoremove)|yum\s+(install|remove)|dnf\s+(install|remove)|pacman\s+(-S|-R)|snap\s+(install|remove)|pip\s+(install|uninstall)|npm\s+install|gem\s+(install|uninstall)|pip3\s+install)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Service control
    private static readonly Regex ServicePattern = new(
        @"\b(systemctl\s+(restart|start|stop|enable|disable|mask)|service\s+\S+\s+(restart|start|stop)|initctl\s+(restart|start|stop)|rc-service\s+\S+\s+(restart|start|stop))\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Config changes (not already caught by destructive)
    private static readonly Regex ConfigPattern = new(
        @"\b(iptables\s+(-A|-I|-D|-P)|nft\s+add|ufw\s+(allow|deny|delete|insert)|sysctl\s+-w|echo\s+.*>\s*/etc/|sed\s+.*-i|chmod\s+.*|chown\s+.*|setfacl|usermod|useradd|groupadd|visudo|crontab\s+.*-e)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Read-only commands
    private static readonly Regex ReadOnlyPattern = new(
        @"\b(cat|ls|grep|find|ps|ss|netstat|lsof|top|htop|df|du|free|uptime|uname|hostname|id|whoami|groups|getent|journalctl\s+--no-pager|iptables\s+-L|nft\s+list|ufw\s+status|sysctl\s+-a|systemctl\s+status|systemctl\s+list|service\s+\S+\s+status|dmesg|lsmod|lspci|lsusb|ip\s+(addr|link|route|neigh)\s+show|ip\s+addr|ss\s+-tlnp|curl\s+-I|wget\s+--spider|test|stat|file|sha256sum|md5sum)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Classifies a single command string by safety impact.
    /// </summary>
    public static CommandSafety Classify(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return CommandSafety.Unknown;

        // Check in order of severity: Destructive > Package > Service > Config > ReadOnly
        if (DestructivePattern.IsMatch(command))
            return CommandSafety.Destructive;

        if (PackagePattern.IsMatch(command))
            return CommandSafety.PackageInstall;

        if (ServicePattern.IsMatch(command))
            return CommandSafety.ServiceRestart;

        if (ConfigPattern.IsMatch(command))
            return CommandSafety.ConfigChange;

        if (ReadOnlyPattern.IsMatch(command))
            return CommandSafety.ReadOnly;

        return CommandSafety.Unknown;
    }
}
