using System.Text.RegularExpressions;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a <see cref="RemediationPlan"/> from a collection of findings.
/// </summary>
public sealed class RemediationPlanBuilder
{
    private readonly IExplanationProvider _explanationProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationPlanBuilder"/> class.
    /// </summary>
    /// <param name="explanationProvider">The explanation provider to parse structured details.</param>
    public RemediationPlanBuilder(IExplanationProvider explanationProvider)
    {
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
    }

    /// <summary>
    /// Builds a remediation plan from the provided findings.
    /// </summary>
    /// <param name="findings">The findings to include in the plan.</param>
    /// <returns>A structured remediation plan.</returns>
    public RemediationPlan Build(IEnumerable<Finding> findings)
    {
        var sections = new List<RemediationSection>();

        foreach (var finding in findings.Where(f => !string.IsNullOrEmpty(f.RuleId)))
        {
            var structured = _explanationProvider.ParseStructuredFromText(finding.Details);
            sections.Add(BuildSection(finding, structured));
        }

        return new RemediationPlan
        {
            Sections = sections
        };
    }

    private static RemediationSection BuildSection(Finding finding, StructuredExplanation structured)
    {
        var applyCommands = ExtractRemediationCommands(structured.SuggestedNextAction);
        var backupCommands = ExtractRemediationCommands(structured.BackupCommands);
        var rollbackCommands = ExtractRemediationCommands(structured.RollbackCommands);
        var verificationCommands = ExtractRemediationCommands(structured.HowToVerify);
        var preconditions = ExtractPreconditions(structured.Preconditions);
        var (rollbackHints, hasExplicitRollbackHints) = ExtractRollbackHints(structured, finding);

        var hasExplicitRollbackCommands = rollbackCommands.Count > 0;
        var hasExplicitRollbackGuidance = hasExplicitRollbackCommands || hasExplicitRollbackHints;

        var riskNote = string.IsNullOrEmpty(structured.Confidence)
            ? structured.Caveats
            : string.IsNullOrEmpty(structured.Caveats)
                ? structured.Confidence
                : $"{structured.Confidence} — {structured.Caveats}";

        var impactPreview = BuildImpactPreview(
            structured,
            applyCommands,
            rollbackCommands,
            rollbackHints,
            hasExplicitRollbackHints,
            verificationCommands);

        return new RemediationSection
        {
            RuleId = finding.RuleId!,
            FindingSummary = $"[{finding.Severity}] {finding.ShortDescription}",
            RiskNote = string.IsNullOrWhiteSpace(riskNote) ? "Review before applying." : riskNote,
            MitreTechniques = finding.MitreTechniques,
            Preconditions = preconditions,
            BackupCommands = backupCommands,
            ApplyCommands = applyCommands,
            RollbackCommands = rollbackCommands,
            RollbackHints = rollbackHints,
            VerificationCommands = verificationCommands,
            HasExplicitRollbackGuidance = hasExplicitRollbackGuidance,
            ImpactPreview = impactPreview
        };
    }

    private static RemediationImpactPreview BuildImpactPreview(
        StructuredExplanation structured,
        IReadOnlyList<RemediationCommand> applyCommands,
        IReadOnlyList<RemediationCommand> rollbackCommands,
        IReadOnlyList<string> rollbackHints,
        bool hasExplicitRollbackHints,
        IReadOnlyList<RemediationCommand> verificationCommands)
    {
        var expectedImpact = BuildExpectedImpact(structured, applyCommands);
        var rollback = BuildRollbackPreview(rollbackCommands, rollbackHints, hasExplicitRollbackHints);
        var verification = BuildVerificationPreview(structured.HowToVerify, verificationCommands);

        return new RemediationImpactPreview
        {
            ExpectedImpact = expectedImpact.Text,
            ExpectedImpactSource = expectedImpact.Source,
            RollbackPath = rollback.Text,
            RollbackPathKind = rollback.Kind,
            VerificationCommand = verification.Text,
            IsVerificationCommand = verification.Kind == RemediationPreviewTextKind.Command,
            VerificationKind = verification.Kind
        };
    }

    private static (string Text, RemediationImpactSource Source) BuildExpectedImpact(
        StructuredExplanation structured,
        IReadOnlyList<RemediationCommand> applyCommands)
    {
        var impactParts = ExtractActionSummaries(structured.SuggestedNextAction).Take(3).ToList();
        if (!string.IsNullOrWhiteSpace(structured.Caveats))
            impactParts.Add($"Caveats: {structured.Caveats}");

        if (impactParts.Count > 0)
            return ($"Applying this step will: {string.Join(" ", impactParts)}", RemediationImpactSource.SuggestedAction);

        if (applyCommands.Count > 0)
            return ($"Applying this step will run {applyCommands.Count} remediation command(s). Review each command before copying.", RemediationImpactSource.ApplyCommands);

        if (!string.IsNullOrWhiteSpace(structured.WhatWasFound))
            return ($"Applying this step should remediate: {structured.WhatWasFound}", RemediationImpactSource.Finding);

        return ("Review the apply commands for expected changes.", RemediationImpactSource.Generic);
    }

    private static (string Text, RemediationPreviewTextKind Kind) BuildRollbackPreview(
        IReadOnlyList<RemediationCommand> rollbackCommands,
        IReadOnlyList<string> rollbackHints,
        bool hasExplicitRollbackHints)
    {
        if (rollbackCommands.Count > 0)
            return (rollbackCommands[0].Command, RemediationPreviewTextKind.Command);

        if (rollbackHints.Count > 0)
        {
            var kind = hasExplicitRollbackHints
                ? RemediationPreviewTextKind.ExplicitGuidance
                : RemediationPreviewTextKind.GenericGuidance;
            return (rollbackHints[0], kind);
        }

        return ("Document the change and keep a backup of original configuration.", RemediationPreviewTextKind.ManualFallback);
    }

    private static (string Text, RemediationPreviewTextKind Kind) BuildVerificationPreview(
        string howToVerify,
        IReadOnlyList<RemediationCommand> verificationCommands)
    {
        foreach (var command in verificationCommands)
        {
            if (IsExplicitVerificationStep(howToVerify, command.Command) || LooksLikeCommand(command))
                return (command.Command, RemediationPreviewTextKind.Command);
        }

        var extractedCommand = ExtractFirstBacktickCommand(howToVerify);
        return extractedCommand != null
            ? (extractedCommand, RemediationPreviewTextKind.Command)
            : ("Run verification manually after applying.", RemediationPreviewTextKind.ManualFallback);
    }

    private static bool IsExplicitVerificationStep(string markdown, string command)
    {
        if (string.IsNullOrWhiteSpace(markdown) || string.IsNullOrWhiteSpace(command))
            return false;

        var pattern = @"^\s*\d+\.\s*.*?`" + Regex.Escape(command) + @"`";
        return Regex.IsMatch(markdown, pattern, RegexOptions.Multiline);
    }

    private static bool LooksLikeCommand(RemediationCommand cmd)
    {
        return cmd.Safety != CommandSafety.Unknown
            || cmd.Analysis.RequiresSudo
            || cmd.Analysis.HasChain
            || cmd.Analysis.HasPipe
            || cmd.Analysis.HasRedirect
            || cmd.Analysis.DownloadsAndExecutes;
    }

    private static string? ExtractFirstBacktickCommand(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return null;

        var match = Regex.Match(markdown, @"`([^`]+)`");
        if (!match.Success)
            return null;

        var candidate = match.Groups[1].Value.Trim();
        var analysis = CommandSafetyClassifier.Analyze(candidate);

        // Reject prose wrapped in backticks (e.g. "The policy should show `DROP`").
        // Only accept candidates that look like actual shell commands.
        var looksLikeCommand = analysis.Safety != CommandSafety.Unknown
            || analysis.RequiresSudo
            || analysis.HasChain
            || analysis.HasPipe
            || analysis.HasRedirect
            || analysis.DownloadsAndExecutes;

        return looksLikeCommand ? candidate : null;
    }

    private static IEnumerable<string> ExtractActionSummaries(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            yield break;

        foreach (var rawLine in markdown.Split('\n'))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("```", StringComparison.Ordinal))
                continue;

            line = Regex.Replace(line, @"^\s*(?:\d+\.\s*|[-*]\s*)", string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var backtickMatch = Regex.Match(line, @"`([^`]+)`");
            if (backtickMatch.Success)
            {
                var label = line[..backtickMatch.Index].Trim().TrimEnd(':');
                yield return string.IsNullOrWhiteSpace(label)
                    ? $"Run `{backtickMatch.Groups[1].Value.Trim()}`."
                    : $"{label}.";
                continue;
            }

            yield return line;
        }
    }

    private static IReadOnlyList<string> ExtractPreconditions(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return Array.Empty<string>();

        return markdown.Split('\n')
            .Select(l => l.Trim().TrimStart('-', '*', ' ').Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .ToList();
    }

    private static IReadOnlyList<RemediationCommand> ExtractRemediationCommands(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown))
            return Array.Empty<RemediationCommand>();

        var commands = new List<RemediationCommand>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // Extract numbered list items with backticks
        var numberedRegex = new Regex(@"^\s*\d+\.\s*(?:[^`]*?\s*)?`([^`]+)`", RegexOptions.Multiline);
        foreach (Match match in numberedRegex.Matches(markdown))
        {
            var cmd = match.Groups[1].Value.Trim();
            if (!string.IsNullOrWhiteSpace(cmd) && seen.Add(cmd))
            {
                var analysis = CommandSafetyClassifier.Analyze(cmd);
                commands.Add(new RemediationCommand
                {
                    Command = cmd,
                    Safety = analysis.Safety,
                    Analysis = analysis
                });
            }
        }

        // Fallback: all backtick commands
        if (commands.Count == 0)
        {
            var backtickRegex = new Regex(@"`([^`]+)`", RegexOptions.Compiled);
            foreach (Match match in backtickRegex.Matches(markdown))
            {
                var cmd = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(cmd) && seen.Add(cmd))
                {
                    var analysis = CommandSafetyClassifier.Analyze(cmd);
                    commands.Add(new RemediationCommand
                    {
                        Command = cmd,
                        Safety = analysis.Safety,
                        Analysis = analysis
                    });
                }
            }
        }

        return commands;
    }

    private static (IReadOnlyList<string> Hints, bool Explicit) ExtractRollbackHints(StructuredExplanation structured, Finding finding)
    {
        // Check if the details markdown contains a Rollback hints section
        if (!string.IsNullOrEmpty(finding.Details))
        {
            var rollbackMatch = Regex.Match(finding.Details, @"\*\*Rollback hints?:\*\*(.*?)(?=\*\*|\z)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (rollbackMatch.Success)
            {
                var lines = rollbackMatch.Groups[1].Value
                    .Split('\n')
                    .Select(l => l.Trim().TrimStart('-', '*', ' ').Trim())
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();
                if (lines.Count > 0)
                    return (lines, true);
            }
        }

        // Generate generic rollback hints based on rule category
        var genericHints = finding.Category switch
        {
            "Firewall" => new[] { "Revert iptables rules with -D instead of -A.", "Restore from `iptables-save` backup." },
            "Port" => new[] { "Re-enable the service if needed.", "Update firewall rules to re-allow the port." },
            "Service" => new[] { "Restart the service with `systemctl start <service>` if needed." },
            "Network" => new[] { "Restore original network configuration.", "Restart networking service to apply changes." },
            _ => new[] { "Document the change and keep a backup of original configuration." }
        };

        return (genericHints.ToList(), false);
    }
}
