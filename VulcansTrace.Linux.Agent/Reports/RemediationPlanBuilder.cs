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

        var impactPreview = BuildImpactPreview(structured, applyCommands, rollbackCommands, rollbackHints, verificationCommands);

        return new RemediationSection
        {
            RuleId = finding.RuleId!,
            FindingSummary = $"[{finding.Severity}] {finding.ShortDescription}",
            RiskNote = string.IsNullOrWhiteSpace(riskNote) ? "Review before applying." : riskNote,
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
        IReadOnlyList<RemediationCommand> verificationCommands)
    {
        var impactParts = ExtractActionSummaries(structured.SuggestedNextAction).ToList();
        if (impactParts.Count == 0 && applyCommands.Count > 0)
            impactParts.Add($"Run {applyCommands.Count} apply command(s) to remediate this finding.");
        if (impactParts.Count == 0 && !string.IsNullOrWhiteSpace(structured.WhatWasFound))
            impactParts.Add($"Remediate finding: {structured.WhatWasFound}");
        if (!string.IsNullOrWhiteSpace(structured.Caveats))
            impactParts.Add($"Caveats: {structured.Caveats}");

        var expectedImpact = impactParts.Count > 0
            ? string.Join(" ", impactParts.Take(3))
            : "Review the apply commands for expected changes.";

        var rollbackPath = rollbackCommands.Count > 0
            ? rollbackCommands[0].Command
            : rollbackHints.Count > 0
                ? rollbackHints[0]
                : "Document the change and keep a backup of original configuration.";

        var verification = BuildVerificationPreview(structured.HowToVerify, verificationCommands);

        return new RemediationImpactPreview
        {
            ExpectedImpact = expectedImpact,
            RollbackPath = rollbackPath,
            VerificationCommand = verification.Text,
            IsVerificationCommand = verification.IsCommand
        };
    }

    private static (string Text, bool IsCommand) BuildVerificationPreview(
        string howToVerify,
        IReadOnlyList<RemediationCommand> verificationCommands)
    {
        foreach (var command in verificationCommands)
        {
            if (IsExplicitVerificationStep(howToVerify, command.Command) || LooksLikeCommand(command))
                return (command.Command, true);
        }

        var extractedCommand = ExtractFirstBacktickCommand(howToVerify);
        return extractedCommand != null
            ? (extractedCommand, true)
            : ("Run verification manually after applying.", false);
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
