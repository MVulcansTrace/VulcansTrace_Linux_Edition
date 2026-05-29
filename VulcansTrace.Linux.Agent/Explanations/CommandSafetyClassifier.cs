using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Classifies shell commands by their likely safety impact using keyword heuristics
/// and detects structural patterns such as chains, pipes, redirects, and remote execution.
/// </summary>
public static class CommandSafetyClassifier
{
    // Destructive commands — highest priority
    private static readonly Regex DestructivePattern = new(
        @"\b(rm\s+-[rfR]\S*|mkfs\S*|dd\s+if=\S*|iptables\s+-F\b|nft\s+flush\b|nft\s+delete\b|ufw\s+reset\b|sysctl\s+--system\s+.*-p|>\s*/dev/sd[a-z]|parted\s+.*mklabel|curl\s+.*\|\s*(sh|bash)\b|wget\s+.*\|\s*(sh|bash)\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Package management
    private static readonly Regex PackagePattern = new(
        @"\b(apt\s+(install|remove|purge|autoremove)|apt-get\s+(install|remove|purge|autoremove)|aptitude\s+(install|remove)|yum\s+(install|remove)|dnf\s+(install|remove)|pacman\s+(-S|-R)|snap\s+(install|remove)|pip\s+(install|uninstall)|pip3\s+(install|uninstall)|npm\s+install|gem\s+(install|uninstall)|zypper\s+(install|remove)|apk\s+add|flatpak\s+install|brew\s+install|choco\s+install)\b",
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

    // Structural patterns
    private static readonly Regex SudoPattern = new(
        @"\bsudo\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SudoShCPattern = new(
        @"\bsudo\s+(sh|bash)\s+-c\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ChainPattern = new(
        @"\s*(&&|\|\||;)\s*",
        RegexOptions.Compiled);

    private static readonly Regex PipePattern = new(
        @"(?<!\|)\s*\|\s*(?!\|)",
        RegexOptions.Compiled);

    private static readonly Regex CompoundSeparatorPattern = new(
        @"(&&|\|\||;|(?<!\|)\|(?!\|))",
        RegexOptions.Compiled);

    private static readonly Regex RedirectPattern = new(
        @"\s*\d*[><][>&]?\s*",
        RegexOptions.Compiled);

    private static readonly Regex DownloadExecutePattern = new(
        @"\b(curl|wget)\s+.*\|\s*(sh|bash)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Performs a full structural and safety analysis of a single command string.
    /// </summary>
    public static CommandAnalysis Analyze(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return new CommandAnalysis();
        }

        var safety = ClassifySafety(command);

        return new CommandAnalysis
        {
            Safety = safety,
            RequiresSudo = SudoPattern.IsMatch(command) || SudoShCPattern.IsMatch(command),
            HasChain = ChainPattern.IsMatch(command),
            HasPipe = PipePattern.IsMatch(command),
            HasRedirect = RedirectPattern.IsMatch(command),
            DownloadsAndExecutes = DownloadExecutePattern.IsMatch(command)
        };
    }

    /// <summary>
    /// Classifies a single command string by safety impact.
    /// </summary>
    public static CommandSafety Classify(string command)
    {
        return Analyze(command).Safety;
    }

    private static CommandSafety ClassifySafety(string command)
    {
        // Check in order of severity: Destructive > Package > Service > Config > ReadOnly
        if (DestructivePattern.IsMatch(command))
            return CommandSafety.Destructive;

        if (PackagePattern.IsMatch(command))
            return CommandSafety.PackageInstall;

        if (ServicePattern.IsMatch(command))
            return CommandSafety.ServiceRestart;

        if (ConfigPattern.IsMatch(command))
            return CommandSafety.ConfigChange;

        if (ChainPattern.IsMatch(command) || PipePattern.IsMatch(command))
            return ClassifyCompoundSafety(command);

        return ClassifySimpleSafety(command);
    }

    private static CommandSafety ClassifyCompoundSafety(string command)
    {
        var segments = CompoundSeparatorPattern
            .Split(command)
            .Where(segment => !string.IsNullOrWhiteSpace(segment)
                && segment is not "&&" and not "||" and not ";" and not "|")
            .Select(ClassifySimpleSafety)
            .ToList();

        if (segments.Count == 0)
            return CommandSafety.Unknown;

        return segments.All(safety => safety == CommandSafety.ReadOnly)
            ? CommandSafety.ReadOnly
            : CommandSafety.Unknown;
    }

    private static CommandSafety ClassifySimpleSafety(string command)
    {
        if (ReadOnlyPattern.IsMatch(command))
            return CommandSafety.ReadOnly;

        return CommandSafety.Unknown;
    }
}
