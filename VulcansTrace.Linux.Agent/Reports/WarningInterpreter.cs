using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Converts raw scanner warnings into concise, user-friendly messages.
/// </summary>
public sealed class WarningInterpreter
{
    /// <summary>
    /// Interprets raw warnings and data-source capabilities for a given intent.
    /// </summary>
    public IReadOnlyList<UserFriendlyWarning> Interpret(
        AgentIntent intent,
        IReadOnlyList<string> warnings,
        IReadOnlyList<DataSourceCapability> capabilities)
    {
        var classified = warnings.Select(Classify).ToList();

        var missingTools = CollapseMissingTools(classified, capabilities, intent);
        var permissionDenied = CollapsePermissionDenied(classified);
        var configMissing = CollapseConfigurationMissing(classified);
        var scannerErrors = CollapseScannerErrors(classified);

        var result = new List<UserFriendlyWarning>();
        result.AddRange(missingTools);
        result.AddRange(permissionDenied);
        result.AddRange(configMissing);
        result.AddRange(scannerErrors);
        return result;
    }

    private static (WarningCategory Category, string Text, string? ToolName, string? Prefix) Classify(string warning)
    {
        var text = warning ?? string.Empty;

        // Permission denied on filesystem paths or scanner summaries
        if (text.Contains("permission denied", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("permission-limited", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("operation not permitted", StringComparison.OrdinalIgnoreCase))
        {
            var path = ExtractPath(text);
            return (WarningCategory.PermissionDenied, text, null, path);
        }

        // Missing command / file not found / tool unavailable
        if (text.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("command not found", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("is not recognized", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("is not available", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("not available", StringComparison.OrdinalIgnoreCase))
        {
            var tool = ExtractToolName(text);
            return (WarningCategory.MissingTool, text, tool, null);
        }

        // Scanner-specific prefixes that imply a missing/limited tool. Checked before the
        // ConfigurationMissing heuristic so a real scanner warning — e.g.
        // "SSH config scan skipped: no sshd_config found." — is attributed to its tool
        // (and surfaces the SSH-specific message) instead of being swallowed as generic
        // config-missing by the greedy "no "/"found" predicate below.
        var scannerPrefix = GetScannerPrefix(text);
        if (!string.IsNullOrEmpty(scannerPrefix))
        {
            // For a firewall scan, prefer the concrete backend named in the message (iptables or
            // nftables) so the user-facing message can name what actually failed; fall back to the
            // generic "firewall" token when neither backend is named.
            var prefixTool = scannerPrefix == "firewall"
                ? ExtractFirewallBackend(text) ?? scannerPrefix
                : scannerPrefix;
            return (WarningCategory.MissingTool, text, prefixTool, null);
        }

        // Configuration missing or skipped because a required file/settings was absent.
        // Note: the bare "found" token was intentionally dropped — the greedy "no " + "found"
        // pair misclassified benign empty-result phrasing ("no issues found", "no findings
        // found") as a missing configuration. "config" and "not found" are retained, which still
        // catches the real cases (e.g. "no PAM configuration files found", "rules not found").
        if ((text.Contains("no ", StringComparison.OrdinalIgnoreCase) ||
             text.Contains("skipped", StringComparison.OrdinalIgnoreCase)) &&
            (text.Contains("config", StringComparison.OrdinalIgnoreCase) ||
             text.Contains("not found", StringComparison.OrdinalIgnoreCase)))
        {
            return (WarningCategory.ConfigurationMissing, text, null, null);
        }

        return (WarningCategory.ScannerError, text, null, null);
    }

    private static string? ExtractPath(string text)
    {
        // Find a filesystem path in the warning, e.g. "find: '/root': Permission denied".
        // Scan quoted spans (single or double) in document order and return the first that looks
        // like a path — requiring a '/' separator avoids mistaking a stray quoted word such as
        // "Permission denied (see 'man sudoers')" for a path and surfacing it as junk in
        // "Affected areas:".
        var i = 0;
        while (i < text.Length)
        {
            var ch = text[i];
            if (ch != '\'' && ch != '"')
            {
                i++;
                continue;
            }
            var close = text.IndexOf(ch, i + 1);
            if (close <= i)
            {
                i++;
                continue;
            }
            var candidate = text.Substring(i + 1, close - i - 1);
            if (candidate.Contains('/'))
                return candidate;
            i = close + 1;
        }
        return null;
    }

    private static string? ExtractToolName(string text)
    {
        // "Firewall scan: iptables failed (...)" -> iptables
        if (text.Contains("iptables", StringComparison.OrdinalIgnoreCase))
            return "iptables";
        if (text.Contains("nftables", StringComparison.OrdinalIgnoreCase) || text.Contains(" nft ", StringComparison.OrdinalIgnoreCase))
            return "nft";
        if (text.Contains("sshd_config", StringComparison.OrdinalIgnoreCase))
            return "sshd_config";
        if (text.Contains("sshd", StringComparison.OrdinalIgnoreCase))
            return "sshd";
        if (text.Contains("ufw", StringComparison.OrdinalIgnoreCase))
            return "ufw";

        // Try to extract a quoted or plain command name before "failed"
        var parts = text.Split(new[] { ' ', '\'', '"', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Equals("failed", StringComparison.OrdinalIgnoreCase) && i > 0)
                return parts[i - 1].TrimEnd(':', ',');
        }

        // Fallback for "<tool> command not found" or "<tool> is not available"
        string? marker = null;
        if (text.Contains("command not found", StringComparison.OrdinalIgnoreCase))
            marker = "command not found";
        else if (text.Contains("is not available", StringComparison.OrdinalIgnoreCase))
            marker = "is not available";
        else if (text.Contains("not available", StringComparison.OrdinalIgnoreCase))
            marker = "not available";

        if (marker != null)
        {
            var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            var before = text.Substring(0, index).Trim();
            var lastToken = before.Split(new[] { ' ', '\'', '"', '(', ')', ':', ',' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            if (!string.IsNullOrWhiteSpace(lastToken))
                return lastToken.TrimEnd(':', ',');
        }

        return null;
    }

    private static string? GetScannerPrefix(string text)
    {
        var prefixes = new[]
        {
            "Firewall scan",
            "SSH config scan",
            "YARA",
            "Filesystem scan",
            "Network scan",
            "Service scan",
            "Port scan",
            "Kernel scan",
            "User account scan",
            "Logging scan",
            "Cron scan",
            "Package scan",
            "Container scan",
            "Kubernetes scan",
            "Process runtime scan",
        };

        foreach (var prefix in prefixes)
        {
            if (text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                // Map scanner prefixes to primary tool names when possible
                return prefix switch
                {
                    "Firewall scan" => "firewall",
                    "SSH config scan" => "sshd_config",
                    _ => null,
                };
            }
        }

        return null;
    }

    /// <summary>
    /// Returns the concrete firewall backend named in a "Firewall scan …" warning when exactly one
    /// is mentioned, so the user-facing message can name it; otherwise null (caller falls back to
    /// the generic "firewall" token). Both-present returns null because the two backends arrive as
    /// separate warnings and are named together later by BuildFirewallMessage.
    /// </summary>
    private static string? ExtractFirewallBackend(string text)
    {
        var hasIptables = text.Contains("iptables", StringComparison.OrdinalIgnoreCase);
        var hasNft = text.Contains("nftables", StringComparison.OrdinalIgnoreCase)
            || text.Contains(" nft ", StringComparison.OrdinalIgnoreCase);
        return (hasIptables, hasNft) switch
        {
            (true, false) => "iptables",
            (false, true) => "nft",
            _ => null,
        };
    }

    /// <summary>
    /// Builds the firewall missing-tool message and suggestion, naming the concrete backend(s)
    /// actually missing rather than always saying "iptables or nftables".
    /// </summary>
    private static (string Message, string Suggestion) BuildFirewallMessage(IReadOnlyList<string> missing)
    {
        var backends = new List<string>(2);
        if (missing.Contains("iptables"))
            backends.Add("iptables");
        if (missing.Contains("nft"))
            backends.Add("nftables");

        if (backends.Count == 0)
        {
            // Firewall check fired without a named backend (e.g. only the "Firewall scan …" prefix
            // or the ufw frontend). Don't claim a specific backend is missing.
            return (
                "This system is missing firewall tooling, so I couldn't inspect active firewall rules.",
                "Install iptables or nftables, or run this on a production Linux host.");
        }

        var named = backends.Count == 1 ? backends[0] : string.Join(" or ", backends);
        return (
            $"This system doesn't have {named} installed, so I couldn't inspect active firewall rules.",
            $"Install {named}, or run this on a production Linux host.");
    }

    private static IReadOnlyList<UserFriendlyWarning> CollapseMissingTools(
        List<(WarningCategory Category, string Text, string? ToolName, string? Prefix)> classified,
        IReadOnlyList<DataSourceCapability> capabilities,
        AgentIntent intent)
    {
        var missing = classified
            .Where(c => c.Category == WarningCategory.MissingTool)
            .Select(c => c.ToolName ?? c.Prefix)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!.ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (missing.Count == 0)
            return Array.Empty<UserFriendlyWarning>();

        // Domain-specific collapsing
        var domainMessages = new List<UserFriendlyWarning>();

        // A missing firewall tool: an iptables/nft backend, the ufw frontend, or a "Firewall scan …"
        // warning (GetScannerPrefix maps that prefix to "firewall"). The prefix token is treated as
        // a real signal here: previously the outer gate matched "firewall" but a redundant inner
        // gate (iptables/nft/ufw only) rejected it, and "firewall" sits in the `covered` set so the
        // generic branch skipped it too — the warning vanished in any audit that wasn't a
        // FirewallCheck. The double gate is gone; BuildFirewallMessage also names the concrete
        // backend(s) instead of always saying "iptables or nftables".
        var hasFirewallSignal = missing.Contains("iptables")
            || missing.Contains("nft")
            || missing.Contains("ufw")
            || missing.Contains("firewall");
        if (intent == AgentIntent.FirewallCheck || hasFirewallSignal)
        {
            var (firewallMessage, firewallSuggestion) = BuildFirewallMessage(missing);
            domainMessages.Add(new UserFriendlyWarning(
                WarningCategory.MissingTool,
                firewallMessage,
                1,
                firewallSuggestion));
        }

        if (intent == AgentIntent.SshCheck || missing.Contains("sshd_config") || missing.Contains("sshd"))
        {
            domainMessages.Add(new UserFriendlyWarning(
                WarningCategory.MissingTool,
                "The SSH daemon config (sshd_config) wasn't found, so SSH hardening checks were skipped.",
                1,
                "Ensure sshd is installed and the config file is accessible."));
        }

        // Generic missing tools not covered above
        var covered = new[] { "iptables", "nft", "firewall", "ufw", "sshd_config", "sshd" };
        var genericMissing = missing.Where(m => !covered.Contains(m, StringComparer.OrdinalIgnoreCase)).ToList();
        foreach (var tool in genericMissing)
        {
            domainMessages.Add(new UserFriendlyWarning(
                WarningCategory.MissingTool,
                $"The tool '{tool}' was not found, so one or more checks were skipped.",
                1,
                $"Install {tool} to enable those checks."));
        }

        return domainMessages;
    }

    private static IReadOnlyList<UserFriendlyWarning> CollapsePermissionDenied(
        List<(WarningCategory Category, string Text, string? ToolName, string? Prefix)> classified)
    {
        var denied = classified.Where(c => c.Category == WarningCategory.PermissionDenied).ToList();
        if (denied.Count == 0)
            return Array.Empty<UserFriendlyWarning>();

        var paths = denied
            .Select(c => c.Prefix)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p!)
            .ToList();

        var prefixes = paths
            .Select(p => p.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var message = denied.Count == 1
            ? "One check was blocked by permissions."
            : $"{denied.Count} checks were blocked by permissions on system paths.";

        if (prefixes.Count > 0)
        {
            message += $" Affected areas: {string.Join(", ", prefixes)}.";
        }

        return new[]
        {
            new UserFriendlyWarning(
                WarningCategory.PermissionDenied,
                message,
                denied.Count,
                "Run with sudo for full visibility into system files and processes."),
        };
    }

    private static IReadOnlyList<UserFriendlyWarning> CollapseConfigurationMissing(
        List<(WarningCategory Category, string Text, string? ToolName, string? Prefix)> classified)
    {
        var config = classified.Where(c => c.Category == WarningCategory.ConfigurationMissing).ToList();
        if (config.Count == 0)
            return Array.Empty<UserFriendlyWarning>();

        var message = config.Count == 1
            ? "One expected configuration file or setting was missing."
            : $"{config.Count} expected configuration files or settings were missing.";

        return new[]
        {
            new UserFriendlyWarning(
                WarningCategory.ConfigurationMissing,
                message,
                config.Count),
        };
    }

    private static IReadOnlyList<UserFriendlyWarning> CollapseScannerErrors(
        List<(WarningCategory Category, string Text, string? ToolName, string? Prefix)> classified)
    {
        var errors = classified.Where(c => c.Category == WarningCategory.ScannerError).ToList();
        if (errors.Count == 0)
            return Array.Empty<UserFriendlyWarning>();

        // Keep scanner errors but don't dump raw text; summarize count.
        return new[]
        {
            new UserFriendlyWarning(
                WarningCategory.ScannerError,
                errors.Count == 1
                    ? "One scanner returned an unexpected error."
                    : $"{errors.Count} scanners returned unexpected errors.",
                errors.Count),
        };
    }
}
