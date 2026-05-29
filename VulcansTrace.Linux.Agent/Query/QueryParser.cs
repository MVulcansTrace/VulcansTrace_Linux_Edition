namespace VulcansTrace.Linux.Agent.Query;

/// <summary>
/// Keyword-based query parser that maps user input to <see cref="AgentIntent"/>.
/// Uses simple scoring — good enough for v1 without external NLP dependencies.
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
        (new[] { "explain", "what does", "mean", "help me understand", "why" }, AgentIntent.ExplainFinding, 1),
        (new[] { "help", "what can you do", "capabilities", "commands" }, AgentIntent.Help, 2),
    };

    /// <inheritdoc />
    public AgentIntent Parse(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return AgentIntent.Help;

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

            if (score > bestScore)
            {
                bestScore = score;
                bestIntent = intent;
            }
        }

        return bestIntent;
    }
}
