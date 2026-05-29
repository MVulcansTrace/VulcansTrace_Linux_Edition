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
            HasExplicitRollbackGuidance = hasExplicitRollbackGuidance
        };
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
