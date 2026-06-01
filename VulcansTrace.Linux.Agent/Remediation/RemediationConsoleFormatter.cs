using System.Text;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Remediation;

/// <summary>
/// Formats remediation plans and execution results for console output.
/// </summary>
public static class RemediationConsoleFormatter
{
    /// <summary>
    /// Formats a remediation plan as a human-readable dry-run preview.
    /// </summary>
    public static string FormatDryRun(RemediationPlan plan, AutoFixPolicy policy)
    {
        var sb = new StringBuilder();
        sb.AppendLine("============================================");
        sb.AppendLine("  VULCANSTRACE AUTO-FIX DRY-RUN PREVIEW");
        sb.AppendLine("============================================");
        sb.AppendLine();
        sb.AppendLine($"Policy: {policy.Describe()}");
        sb.AppendLine($"Total findings: {plan.TotalSections}");
        sb.AppendLine();

        for (int i = 0; i < plan.Sections.Count; i++)
        {
            var section = plan.Sections[i];
            sb.AppendLine($"[{i + 1}/{plan.TotalSections}] {section.RuleId}: {section.FindingSummary}");
            sb.AppendLine($"    Risk: {section.RiskNote}");

            var permittedApply = section.ApplyCommands.Where(c => policy.IsPermitted(c.Safety)).ToList();
            var blockedApply = section.ApplyCommands.Where(c => !policy.IsPermitted(c.Safety)).ToList();

            if (permittedApply.Count == 0 && blockedApply.Count == 0)
            {
                sb.AppendLine("    → No apply commands available.");
            }
            else
            {
                if (permittedApply.Count > 0)
                {
                    sb.AppendLine($"    → Would execute {permittedApply.Count} command(s):");
                    foreach (var cmd in permittedApply)
                    {
                        sb.AppendLine($"       [ {cmd.Safety} ] {cmd.Command}");
                    }
                }
                if (blockedApply.Count > 0)
                {
                    sb.AppendLine($"    → Would SKIP {blockedApply.Count} command(s) (policy):");
                    foreach (var cmd in blockedApply)
                    {
                        sb.AppendLine($"       [ {cmd.Safety} ] {cmd.Command}");
                    }
                }
            }

            if (section.BackupCommands.Count > 0)
            {
                sb.AppendLine($"    → Backup: {section.BackupCommands.Count} command(s)");
            }
            if (section.VerificationCommands.Count > 0)
            {
                sb.AppendLine($"    → Verify: {section.VerificationCommands.Count} command(s)");
            }
            if (section.RollbackCommands.Count > 0)
            {
                sb.AppendLine($"    → Rollback: {section.RollbackCommands.Count} command(s) available");
            }
            else if (section.RollbackHints.Count > 0)
            {
                sb.AppendLine($"    → Rollback hints: {section.RollbackHints.Count} hint(s)");
            }

            sb.AppendLine();
        }

        sb.AppendLine("============================================");
        sb.AppendLine("  END OF DRY-RUN — NO CHANGES WERE MADE");
        sb.AppendLine("============================================");
        return sb.ToString();
    }

    /// <summary>
    /// Formats the result of an execution run for console output.
    /// </summary>
    public static string FormatExecutionResult(RemediationExecutionResult result)
    {
        var sb = new StringBuilder();
        var prefix = result.IsDryRun ? "[DRY-RUN] " : "";

        sb.AppendLine();
        sb.AppendLine($"{prefix}Remediation complete.");
        sb.AppendLine(result.Summary);
        sb.AppendLine();

        foreach (var section in result.Sections)
        {
            if (section.Skipped)
            {
                sb.AppendLine($"⏭️  {section.RuleId}: SKIPPED — {section.SkipReason}");
                continue;
            }

            var hasFailures = section.CommandsFailed > 0;
            var icon = hasFailures ? "❌" : "✅";
            sb.AppendLine($"{icon} {section.RuleId}: {section.FindingSummary}");

            if (section.RollbackResults.Count > 0)
            {
                sb.AppendLine("   🔄 Rollback triggered due to apply failure.");
            }

            foreach (var cmd in section.BackupResults.Concat(section.ApplyResults).Concat(section.VerificationResults).Concat(section.RollbackResults))
            {
                if (cmd.Skipped)
                {
                    sb.AppendLine($"   ⏭️  [{cmd.Phase}] {cmd.Command}");
                    sb.AppendLine($"      → Skipped: {cmd.SkipReason}");
                }
                else if (cmd.Success)
                {
                    sb.AppendLine($"   ✅ [{cmd.Phase}] {cmd.Command}");
                    if (!string.IsNullOrWhiteSpace(cmd.StdOut))
                    {
                        var lines = cmd.StdOut.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)).Take(3);
                        foreach (var line in lines)
                        {
                            sb.AppendLine($"      {line.Trim()}");
                        }
                        if (cmd.StdOut.Split('\n').Length > 3)
                        {
                            sb.AppendLine($"      ... ({cmd.StdOut.Split('\n').Length - 3} more lines)");
                        }
                    }
                }
                else
                {
                    sb.AppendLine($"   ❌ [{cmd.Phase}] {cmd.Command}");
                    sb.AppendLine($"      Exit code: {cmd.ExitCode}");
                    if (!string.IsNullOrWhiteSpace(cmd.StdErr))
                    {
                        var lines = cmd.StdErr.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)).Take(3);
                        foreach (var line in lines)
                        {
                            sb.AppendLine($"      ERR: {line.Trim()}");
                        }
                        if (cmd.StdErr.Split('\n').Length > 3)
                        {
                            sb.AppendLine($"      ... ({cmd.StdErr.Split('\n').Length - 3} more error lines)");
                        }
                    }
                }
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }
}
