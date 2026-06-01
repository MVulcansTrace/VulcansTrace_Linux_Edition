using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Keyword-based query parser that maps user input to <see cref="AgentQuery"/>.
/// Uses simple scoring — good enough for v1 without external NLP dependencies.
/// Also extracts finding references (rule IDs, category keywords) from the query.
/// </summary>
public sealed class QueryParser : IQueryParser
{
    private static readonly (string[] Keywords, AgentIntent Intent, int Weight)[] Patterns =
    {
        (new[] { "secure", "safe", "audit", "full check", "health", "scan everything", "check everything" }, AgentIntent.FullAudit, 2),
        (new[] { "firewall", "iptables", "nftables", "rules", "drop", "accept", "filter" }, AgentIntent.FirewallCheck, 2),
        (new[] { "network", "connection", "talking", "who", "route", "interface", "ip addr", "traffic" }, AgentIntent.NetworkCheck, 2),
        (new[] { "service", "running", "daemon", "systemctl", "unit" }, AgentIntent.ServiceCheck, 2),
        (new[] { "port", "open", "listening", "ss", "netstat" }, AgentIntent.PortCheck, 2),
        (new[] { "ssh", "sshd", "ssh config", "ssh hardening", "permitrootlogin", "passwordauthentication" }, AgentIntent.SshCheck, 2),
        (new[] { "file permission", "permission", "permissions", "filepermission", "chmod", "chown", "shadow", "passwd" }, AgentIntent.FilePermissionCheck, 2),
        (new[] { "filesystem", "world-writable", "suid", "sgid", "sticky bit", "unowned", "tmp hardening" }, AgentIntent.FilesystemAuditCheck, 2),
        (new[] { "kernel", "sysctl", "hardening", "aslr", "secure boot", "module loading", "ip forward", "icmp redirect" }, AgentIntent.KernelCheck, 2),
        (new[] { "user", "account", "password", "passwd", "shadow", "uid", "pam", "login.defs", "pwquality", "faillock", "lockout" }, AgentIntent.UserAccountCheck, 2),
        (new[] { "logging", "log", "rsyslog", "journald", "auditd", "logrotate", "forwarding", "syslog" }, AgentIntent.LoggingAuditCheck, 2),
        (new[] { "cron", "crontab", "scheduled job", "cron job" }, AgentIntent.CronJobCheck, 2),
        (new[] { "package", "vulnerability", "cve", "security update", "apt", "upgradeable", "patch" }, AgentIntent.PackageVulnerabilityCheck, 2),
        (new[] { "explain", "what does", "mean", "why" }, AgentIntent.ExplainFinding, 2),
        (new[] { "changed", "since last", "what changed", "difference", "diff", "compare" }, AgentIntent.ShowChanges, 2),
        (new[] { "why critical", "critical findings", "why high", "why severe", "why is this critical" }, AgentIntent.ExplainCritical, 2),
        (new[] { "only", "just show", "show me", "filter" }, AgentIntent.FilterCategory, 3),
        (new[] { "fix first", "what should i fix", "prioritize", "remediation plan", "what to do" }, AgentIntent.PrioritizeRemediation, 2),
        (new[] { "fix ", "remediate", "resolve" }, AgentIntent.FixFinding, 3),
        (new[] { "suppressed", "which are suppressed", "hidden findings", "silenced" }, AgentIntent.ListSuppressed, 2),
        (new[] { "set baseline", "save baseline", "snapshot baseline", "mark as baseline", "known good" }, AgentIntent.SetBaseline, 3),
        (new[] { "drift", "check drift", "baseline drift", "deviated", "changed from baseline" }, AgentIntent.CheckDrift, 3),
        (new[] { "show baseline", "view baseline", "current baseline", "what is my baseline" }, AgentIntent.ShowBaseline, 3),
        (new[] { "risk score", "risk grade", "what's my risk", "how risky", "risk assessment", "overall risk" }, AgentIntent.RiskScore, 2),
        (new[] { "help", "what can you do", "capabilities", "commands" }, AgentIntent.Help, 2),
    };

    private static readonly Regex RuleIdPattern = new(@"[A-Za-z]{2,}-\d{3,}", RegexOptions.Compiled);

    private static readonly string[] CategoryKeywords =
    {
        "firewall", "ssh", "port", "network", "service", "icmp", "iptables", "nftables", "file", "permission", "filepermission", "filesystem", "suid", "world-writable", "kernel", "user", "account", "password", "uid", "pam", "logging", "rsyslog", "journald", "audit", "auditd", "logrotate", "forwarding", "package", "cve"
    };

    /// <inheritdoc />
    public AgentQuery Parse(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new AgentQuery(AgentIntent.Help);

        var normalized = query.ToLowerInvariant().Trim();
        var bestIntent = AgentIntent.Help;
        var bestScore = 0;

        foreach (var (keywords, intent, weight) in Patterns)
        {
            var score = 0;
            foreach (var keyword in keywords)
            {
                if (normalized.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    score += weight;
                }
            }

            if (score >= bestScore)
            {
                bestScore = score;
                bestIntent = intent;
            }
        }

        var targetReference = ExtractTargetReference(query, bestIntent);
        return new AgentQuery(bestIntent, targetReference);
    }

    private static string? ExtractTargetReference(string rawQuery, AgentIntent intent)
    {
        if (intent != AgentIntent.ExplainFinding && intent != AgentIntent.FilterCategory && intent != AgentIntent.FixFinding)
            return null;

        // Look for rule IDs like FW-001, PORT-002, etc.
        var ruleMatch = RuleIdPattern.Match(rawQuery);
        if (ruleMatch.Success)
        {
            return ruleMatch.Value;
        }

        // Look for category keywords
        var normalized = rawQuery.ToLowerInvariant();
        foreach (var keyword in CategoryKeywords)
        {
            if (normalized.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return keyword;
            }
        }

        return null;
    }
}
