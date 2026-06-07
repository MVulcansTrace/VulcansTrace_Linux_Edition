using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Explanations;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Predicts the operational and safety impact of applying a remediation before
/// any commands are executed. Derives risk metrics from the remediation section's
/// commands, safety classifications, and finding metadata.
/// </summary>
public static class RemediationImpactSimulator
{
    private static readonly Regex SystemctlRestartRegex = new(
        @"(?<!\w)systemctl\s+(restart|reload|try-restart|force-reload)(?![\w-])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Individual lockout regexes — ordered from most specific to least specific.
    // Each regex uses \s+ for whitespace tolerance, matching the detection logic.
    private static readonly Regex IptablesInputDropRegex = new(
        @"iptables\s+-P\s+INPUT\s+DROP",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IptablesPort22BlockRegex = new(
        @"iptables\s+.*--dport\s+22\s+.*-j\s+(DROP|REJECT)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UfwDeny22Regex = new(
        @"ufw\s+deny\s+22",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UfwDefaultDenyRegex = new(
        @"ufw\s+default\s+deny\s+incoming",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SshConfigRegex = new(
        @"(sshd_config|/etc/ssh/)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Analyzes a remediation section and produces an enriched impact preview
    /// that includes risk before/after, command counts, rollback availability,
    /// restart impact, and lockout risk.
    /// </summary>
    /// <param name="section">The remediation section to analyze.</param>
    /// <param name="existingPreview">The existing impact preview to enrich.</param>
    /// <returns>A new impact preview with simulation fields populated.</returns>
    public static RemediationImpactPreview Simulate(RemediationSection section, RemediationImpactPreview existingPreview)
    {
        var (hasRestart, restartDesc) = AnalyzeRestartImpact(section);
        var (hasLockout, lockoutDesc) = AnalyzeLockoutRisk(section);

        return existingPreview with
        {
            RiskBefore = BuildRiskBefore(section),
            ExpectedRiskAfter = BuildExpectedRiskAfter(section),
            CommandCount = CountCommandsInvolved(section),
            RollbackAvailable = section.HasExplicitRollbackGuidance
                && (section.RollbackCommands.Count > 0 || section.RollbackHints.Count > 0),
            HasRestartImpact = hasRestart,
            HasLockoutRisk = hasLockout,
            RestartImpactDescription = restartDesc,
            LockoutRiskDescription = lockoutDesc
        };
    }

    private static string BuildRiskBefore(RemediationSection section)
    {
        var severity = ParseSeverityFromSummary(section.FindingSummary);
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(severity))
            parts.Add($"[{severity}]");
        if (!string.IsNullOrWhiteSpace(section.RiskNote))
            parts.Add(section.RiskNote);
        return parts.Count > 0 ? string.Join(" ", parts) : "Review before applying.";
    }

    private static string BuildExpectedRiskAfter(RemediationSection section)
    {
        if (section.ApplyCommands.Count == 0)
            return "Manual review required — no automated apply commands available.";

        var hasConfigChange = section.ApplyCommands.Any(c => c.Safety == CommandSafety.ConfigChange);
        var hasServiceRestart = section.ApplyCommands.Any(c => c.Safety == CommandSafety.ServiceRestart);
        var hasDestructive = section.ApplyCommands.Any(c => c.Safety == CommandSafety.Destructive);

        if (hasDestructive)
            return "Finding should be resolved after applying. Destructive changes cannot be undone — ensure backups are in place.";

        if (hasServiceRestart)
            return "Finding should be resolved after applying. A service restart will be required.";

        if (hasConfigChange)
            return "Finding should be resolved after applying configuration changes.";

        return "Finding should be resolved after applying.";
    }

    private static (bool HasRestart, string Description) AnalyzeRestartImpact(RemediationSection section)
    {
        var reasons = new List<string>();

        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var cmd in ImpactCommands(section))
        {
            if (cmd.Safety == CommandSafety.ReadOnly)
                continue;

            if (cmd.Safety == CommandSafety.ServiceRestart)
            {
                if (seen.Add("service-restart"))
                    reasons.Add("One or more apply commands require a service restart.");
                continue;
            }

            var stripped = StripShellComment(cmd.Command);
            if (SystemctlRestartRegex.IsMatch(stripped) && seen.Add(cmd.Command))
                reasons.Add($"Command involves service restart/reload: `{cmd.Command}`");
        }

        return (reasons.Count > 0, string.Join(" | ", reasons));
    }

    private static (bool HasLockout, string Description) AnalyzeLockoutRisk(RemediationSection section)
    {
        var reasons = new List<string>();
        var seen = new HashSet<string>();

        foreach (var cmd in ImpactCommands(section))
        {
            if (cmd.Safety == CommandSafety.ReadOnly)
                continue;

            var stripped = StripShellComment(cmd.Command);
            var reason = ClassifyLockoutReason(stripped);
            if (!string.IsNullOrEmpty(reason) && seen.Add(reason))
                reasons.Add(reason);
        }

        return (reasons.Count > 0, string.Join(" | ", reasons));
    }

    /// <summary>
    /// Yields commands that may affect the system before or during apply. Verification
    /// and rollback commands are excluded because they run after apply or during recovery.
    /// </summary>
    private static IEnumerable<RemediationCommand> ImpactCommands(RemediationSection section)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var cmd in section.ApplyCommands)
        {
            if (seen.Add(cmd.Command))
                yield return cmd;
        }

        foreach (var cmd in section.BackupCommands)
        {
            if (seen.Add(cmd.Command))
                yield return cmd;
        }

        foreach (var cm in section.CountermeasureCommands)
        {
            if (!seen.Add(cm.Command))
                continue;

            yield return new RemediationCommand
            {
                Command = cm.Command,
                Safety = cm.Safety,
                Analysis = cm.Analysis
            };
        }
    }

    private static int CountCommandsInvolved(RemediationSection section)
    {
        return ImpactCommands(section).Count();
    }

    private static string? ClassifyLockoutReason(string command)
    {
        if (IptablesInputDropRegex.IsMatch(command))
            return "Command sets default INPUT policy to DROP — existing connections may be terminated and new SSH sessions blocked.";

        if (IptablesPort22BlockRegex.IsMatch(command))
            return "Command blocks port 22 — SSH access will be denied. Ensure an alternative access path exists.";

        if (UfwDeny22Regex.IsMatch(command))
            return "UFW will deny port 22 — SSH access will be blocked.";

        if (UfwDefaultDenyRegex.IsMatch(command))
            return "UFW will deny all incoming connections — ensure SSH or other management access is explicitly allowed first.";

        if (SshConfigRegex.IsMatch(command))
            return "Command modifies SSH configuration — a syntax error or overly restrictive rule may lock you out.";

        return null;
    }

    private static string StripShellComment(string command)
    {
        for (int i = 0; i < command.Length; i++)
        {
            if (command[i] == '#' && (i == 0 || char.IsWhiteSpace(command[i - 1])))
                return command[..i].TrimEnd();
        }
        return command;
    }

    private static readonly Regex SeverityBracketRegex = new(
        @"^\[([A-Za-z]+)\]",
        RegexOptions.Compiled);

    private static string ParseSeverityFromSummary(string summary)
    {
        if (string.IsNullOrWhiteSpace(summary))
            return string.Empty;

        var match = SeverityBracketRegex.Match(summary);
        return match.Success ? match.Groups[1].Value : string.Empty;
    }
}
