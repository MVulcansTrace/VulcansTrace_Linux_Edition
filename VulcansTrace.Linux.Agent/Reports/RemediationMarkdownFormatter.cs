using System.Text;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Formats a <see cref="RemediationPlan"/> as a Markdown document.
/// </summary>
public sealed class RemediationMarkdownFormatter
{
    /// <summary>
    /// Formats the remediation plan as a Markdown string.
    /// </summary>
    /// <param name="plan">The plan to format.</param>
    /// <returns>A Markdown document.</returns>
    public string Format(RemediationPlan plan)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# VulcansTrace Remediation Plan");
        sb.AppendLine();
        sb.AppendLine($"> **Generated:** {plan.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"> **Total findings:** {plan.TotalSections}");
        sb.AppendLine();
        sb.AppendLine("> **IMPORTANT:** Review all commands before running. This is a preview, not an automated fix.");
        sb.AppendLine("> **WARNING:** Some changes may impact system availability. Test in a non-production environment first.");
        sb.AppendLine();

        for (int i = 0; i < plan.Sections.Count; i++)
        {
            var section = plan.Sections[i];
            sb.AppendLine($"## {i + 1}. {section.RuleId}: {section.FindingSummary}");
            sb.AppendLine();

            sb.AppendLine($"**Risk:** {section.RiskNote}");
            sb.AppendLine();

            if (section.RemediationCommands.Count > 0)
            {
                sb.AppendLine("### Remediation Commands");
                sb.AppendLine();
                foreach (var cmd in section.RemediationCommands)
                {
                    sb.AppendLine($"> **Safety:** {cmd.Safety}");
                    sb.AppendLine($"```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine($"```");
                }
                sb.AppendLine();
            }

            if (section.RollbackHints.Count > 0)
            {
                sb.AppendLine("### Rollback Hints");
                sb.AppendLine();
                foreach (var hint in section.RollbackHints)
                {
                    sb.AppendLine($"- {hint}");
                }
                sb.AppendLine();
            }

            if (section.VerificationCommands.Count > 0)
            {
                sb.AppendLine("### Verification Commands");
                sb.AppendLine();
                foreach (var cmd in section.VerificationCommands)
                {
                    sb.AppendLine($"> **Safety:** {cmd.Safety}");
                    sb.AppendLine($"```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine($"```");
                }
                sb.AppendLine();
            }

            sb.AppendLine("---");
            sb.AppendLine();
        }

        sb.AppendLine("## Post-Remediation Checklist");
        sb.AppendLine();
        sb.AppendLine("- [ ] All commands were reviewed before execution.");
        sb.AppendLine("- [ ] A backup of original configuration was created.");
        sb.AppendLine("- [ ] Changes were tested in a non-production environment where possible.");
        sb.AppendLine("- [ ] Verification commands confirm the intended state.");
        sb.AppendLine("- [ ] Rollback plan is documented and accessible.");
        sb.AppendLine();

        return sb.ToString();
    }
}
