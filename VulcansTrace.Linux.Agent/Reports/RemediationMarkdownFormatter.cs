using System.Text;
using VulcansTrace.Linux.Agent.Sessions;

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

        var validation = RemediationPlanValidator.Validate(plan);
        if (validation.IsValid)
        {
            sb.AppendLine("> **Guardrails:** All risky, unclassified, or config-changing commands include rollback guidance.");
        }
        else
        {
            sb.AppendLine("> **Guardrails:** Some sections lack explicit rollback guidance. Export may be blocked.");
        }
        sb.AppendLine();

        for (int i = 0; i < plan.Sections.Count; i++)
        {
            var section = plan.Sections[i];
            sb.AppendLine($"## {i + 1}. {section.RuleId}: {section.FindingSummary}");
            sb.AppendLine();

            sb.AppendLine($"**Risk:** {section.RiskNote}");
            sb.AppendLine();

            if (section.MitreTechniques.Count > 0)
            {
                sb.AppendLine("> **MITRE ATT&CK:** " + string.Join(", ", section.MitreTechniques.Select(m => $"{m.TechniqueId} ({m.TechniqueName})")));
                sb.AppendLine();
            }

            if (section.ImpactPreview != null)
            {
                sb.AppendLine("> **Impact Preview**");
                sb.AppendLine($"> **Impact:** {section.ImpactPreview.ExpectedImpact}");
                var rollbackFormatted = section.ImpactPreview.RollbackPathKind == RemediationPreviewTextKind.Command
                    ? $"`{section.ImpactPreview.RollbackPath}`"
                    : section.ImpactPreview.RollbackPath;
                var verificationFormatted = section.ImpactPreview.VerificationKind == RemediationPreviewTextKind.Command
                    ? $"`{section.ImpactPreview.VerificationCommand}`"
                    : section.ImpactPreview.VerificationCommand;
                sb.AppendLine($"> **Rollback:** {rollbackFormatted}");
                sb.AppendLine($"> **Verify:** {verificationFormatted}");
                sb.AppendLine();
            }

            if (section.Preconditions.Count > 0)
            {
                sb.AppendLine("### Preconditions");
                sb.AppendLine();
                foreach (var pre in section.Preconditions)
                {
                    sb.AppendLine($"- [ ] {pre}");
                }
                sb.AppendLine();
            }

            if (section.BackupCommands.Count > 0)
            {
                sb.AppendLine("### Backup Commands");
                sb.AppendLine();
                foreach (var cmd in section.BackupCommands)
                {
                    sb.AppendLine($"> **Safety:** {cmd.Safety}");
                    AppendCommandWarnings(sb, cmd);
                    sb.AppendLine("```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine("```");
                }
                sb.AppendLine();
            }

            if (section.ApplyCommands.Count > 0)
            {
                sb.AppendLine("### Apply Commands");
                sb.AppendLine();
                foreach (var cmd in section.ApplyCommands)
                {
                    sb.AppendLine($"> **Safety:** {cmd.Safety}");
                    AppendCommandWarnings(sb, cmd);
                    sb.AppendLine("```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine("```");
                }
                sb.AppendLine();
            }

            if (section.RollbackCommands.Count > 0)
            {
                sb.AppendLine("### Rollback Commands");
                sb.AppendLine();
                foreach (var cmd in section.RollbackCommands)
                {
                    sb.AppendLine($"> **Safety:** {cmd.Safety}");
                    AppendCommandWarnings(sb, cmd);
                    sb.AppendLine("```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine("```");
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
                    AppendCommandWarnings(sb, cmd);
                    sb.AppendLine("```bash");
                    sb.AppendLine(cmd.Command);
                    sb.AppendLine("```");
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

    public string FormatSession(RemediationSession session)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# VulcansTrace Remediation Session Report");
        sb.AppendLine();
        sb.AppendLine($"> **Session ID:** {session.SessionId}");
        sb.AppendLine($"> **Created:** {session.CreatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"> **Status:** {session.Status}");
        sb.AppendLine();

        if (session.Timeline.Count > 0)
        {
            sb.AppendLine("## Timeline");
            sb.AppendLine();
            foreach (var evt in session.Timeline)
            {
                sb.AppendLine($"- {evt.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC — {evt.Type}: {evt.Title}");
                if (!string.IsNullOrWhiteSpace(evt.Details))
                {
                    sb.AppendLine($"  - {evt.Details}");
                }
            }
            sb.AppendLine();
        }

        if (session.Notes.Count > 0)
        {
            AppendNotesSection(sb, session.Notes);
        }

        if (session.BlockedReasons.Count > 0)
        {
            sb.AppendLine("## Blocked Steps");
            sb.AppendLine();
            foreach (var reason in session.BlockedReasons)
            {
                sb.AppendLine($"- {reason}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("## Step States");
        sb.AppendLine();
        foreach (var (ruleId, state) in session.StepStates)
        {
            sb.AppendLine($"- **{ruleId}:** {state}");
        }
        sb.AppendLine();

        if (session.RemediationPlan.Sections.Count > 0)
        {
            sb.AppendLine("## Remediation Plan");
            sb.AppendLine();
            sb.Append(Format(session.RemediationPlan));
        }

        if (session.BeforeSnapshot != null)
        {
            sb.AppendLine("## Before Snapshot");
            sb.AppendLine();
            sb.AppendLine($"> **Captured:** {session.BeforeSnapshot.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"> **Intent:** {session.BeforeSnapshot.Intent}");
            sb.AppendLine();
            foreach (var f in session.BeforeSnapshot.Findings)
            {
                sb.AppendLine($"- [{f.RuleId}] [{f.Severity}] {f.ShortDescription}");
            }
            sb.AppendLine();
        }

        if (session.VerificationResult != null)
        {
            var v = session.VerificationResult;
            sb.AppendLine("## Verification Result");
            sb.AppendLine();
            sb.AppendLine($"> **Verified at:** {v.VerifiedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine();
            sb.AppendLine(v.DiffNarrative);
            sb.AppendLine();

            if (v.FixedFindings.Count > 0)
            {
                sb.AppendLine("### Fixed");
                sb.AppendLine();
                foreach (var f in v.FixedFindings)
                {
                    sb.AppendLine($"- ✓ [{f.RuleId}] {f.ShortDescription}");
                }
                sb.AppendLine();
            }

            if (v.UnchangedFindings.Count > 0)
            {
                sb.AppendLine("### Unchanged");
                sb.AppendLine();
                foreach (var f in v.UnchangedFindings)
                {
                    sb.AppendLine($"- [{f.RuleId}] {f.ShortDescription}");
                }
                sb.AppendLine();
            }

            if (v.NewFindings.Count > 0)
            {
                sb.AppendLine("### New Findings");
                sb.AppendLine();
                foreach (var f in v.NewFindings)
                {
                    sb.AppendLine($"- ⚠ [{f.RuleId}] {f.ShortDescription}");
                }
                sb.AppendLine();
            }

            if (v.WorsenedFindings.Count > 0)
            {
                sb.AppendLine("### Worsened");
                sb.AppendLine();
                foreach (var f in v.WorsenedFindings)
                {
                    sb.AppendLine($"- ✗ [{f.RuleId}] {f.OldSeverity} → {f.NewSeverity}: {f.ShortDescription}");
                }
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    private static void AppendNotesSection(StringBuilder sb, IReadOnlyList<SessionNote> notes)
    {
        sb.AppendLine("## Notes");
        sb.AppendLine();

        var sessionNotes = notes.Where(n => string.IsNullOrEmpty(n.RuleId)).ToList();
        var stepNotes = notes.Where(n => !string.IsNullOrEmpty(n.RuleId)).GroupBy(n => n.RuleId!).ToList();

        if (sessionNotes.Count > 0)
        {
            sb.AppendLine("### Session Notes");
            sb.AppendLine();
            foreach (var note in sessionNotes)
            {
                sb.AppendLine($"- {note.CreatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC — {note.Text}");
                foreach (var link in note.EvidenceLinks)
                {
                    sb.AppendLine($"  - Evidence: `{link}`");
                }
            }
            sb.AppendLine();
        }

        if (stepNotes.Count > 0)
        {
            sb.AppendLine("### Step Notes");
            sb.AppendLine();
            foreach (var group in stepNotes)
            {
                sb.AppendLine($"#### {group.Key}");
                sb.AppendLine();
                foreach (var note in group)
                {
                    sb.AppendLine($"- {note.CreatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC — {note.Text}");
                    foreach (var link in note.EvidenceLinks)
                    {
                        sb.AppendLine($"  - Evidence: `{link}`");
                    }
                }
                sb.AppendLine();
            }
        }
    }

    private static void AppendCommandWarnings(StringBuilder sb, RemediationCommand cmd)
    {
        if (cmd.Analysis.RequiresSudo)
            sb.AppendLine("> ⚠️ Requires sudo");

        if (cmd.Analysis.HasChain)
            sb.AppendLine("> ⚠️ Contains chain operators");

        if (cmd.Analysis.HasPipe)
            sb.AppendLine("> ⚠️ Contains pipe");

        if (cmd.Analysis.HasRedirect)
            sb.AppendLine("> ⚠️ Contains redirects");

        if (cmd.Analysis.DownloadsAndExecutes)
            sb.AppendLine("> ⚠️ Downloads and executes remote code");
    }
}
