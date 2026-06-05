using System.Net;
using System.Net.Sockets;
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

    /// <summary>
    /// Builds an incident-response countermeasure plan from critical chains detected in a Trace Map.
    /// </summary>
    public RemediationPlan BuildCountermeasures(TraceMapResult traceMap)
    {
        var sections = new List<RemediationSection>();
        var findingById = traceMap.Findings.ToDictionary(f => f.Id);
        var blockedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var chain in traceMap.CriticalChains)
        {
            if (chain.FindingIds.Count < 3)
                continue;

            var chainFindings = chain.FindingIds
                .Select(id => findingById.TryGetValue(id, out var finding) ? finding : null)
                .Where(finding => finding != null)
                .Select(finding => finding!)
                .ToList();

            if (chainFindings.Count < 3)
                continue;

            var beaconing = chainFindings.FirstOrDefault(f => IsCategory(f, FindingCategories.Beaconing));
            var lateral = chainFindings.FirstOrDefault(f => IsCategory(f, FindingCategories.LateralMovement));
            var privEsc = chainFindings.FirstOrDefault(f => IsCategory(f, FindingCategories.PrivilegeEscalation));

            if (beaconing == null || lateral == null || privEsc == null)
                continue;

            var compromisedHost = lateral.SourceHost;

            if (!TryExtractIpAddress(beaconing.Target, out var attackerAddress, out var attackerIp))
            {
                sections.Add(new RemediationSection
                {
                    RuleId = "COUNTERMEASURE-BLOCKED",
                    FindingSummary = $"[Critical] Incident response blocked on {compromisedHost}",
                    RiskNote = $"Countermeasure generation blocked: beaconing target '{beaconing.Target}' does not contain a valid IP address.",
                    MitreTechniques = Array.Empty<MitreTechnique>(),
                    Preconditions = Array.Empty<string>(),
                    BackupCommands = Array.Empty<RemediationCommand>(),
                    ApplyCommands = Array.Empty<RemediationCommand>(),
                    RollbackCommands = Array.Empty<RemediationCommand>(),
                    RollbackHints = Array.Empty<string>(),
                    VerificationCommands = Array.Empty<RemediationCommand>(),
                    HasExplicitRollbackGuidance = true,
                    CountermeasureCommands = Array.Empty<CountermeasureCommand>()
                });
                continue;
            }

            // M-1 Fix: Deduplicate by attacker IP — skip if we already generated a rule for this IP
            if (!blockedIps.Add(attackerIp))
                continue;

            var firewallTool = attackerAddress.AddressFamily == AddressFamily.InterNetworkV6 ? "ip6tables" : "iptables";
            var iptablesApply = $"sudo {firewallTool} -A INPUT -s {attackerIp} -j DROP";
            var iptablesRollback = $"sudo {firewallTool} -D INPUT -s {attackerIp} -j DROP";

            var auditKey = BuildAuditKey(attackerIp);
            var auditdApply = $"sudo auditctl -a always,exit -F arch=b64 -S connect -k {auditKey}";
            var auditdRollback = $"sudo auditctl -d always,exit -F arch=b64 -S connect -k {auditKey}";

            var iptablesAnalysis = new CommandAnalysis { Safety = CommandSafety.ConfigChange, RequiresSudo = true };
            var auditdAnalysis = new CommandAnalysis { Safety = CommandSafety.ConfigChange, RequiresSudo = true };

            var countermeasures = new List<CountermeasureCommand>
            {
                new()
                {
                    Command = iptablesApply,
                    RollbackCommand = iptablesRollback,
                    Safety = iptablesAnalysis.Safety,
                    Analysis = iptablesAnalysis,
                    Type = CountermeasureType.IptablesDrop,
                    TargetHost = attackerIp
                },
                new()
                {
                    Command = auditdApply,
                    RollbackCommand = auditdRollback,
                    Safety = auditdAnalysis.Safety,
                    Analysis = auditdAnalysis,
                    Type = CountermeasureType.AuditdMonitor,
                    TargetHost = attackerIp
                }
            };

            // C-1 Fix: Populate ApplyCommands so RemediationExecutor actually runs the countermeasures
            var applyCommands = new List<RemediationCommand>
            {
                new() { Command = iptablesApply, Safety = iptablesAnalysis.Safety, Analysis = iptablesAnalysis },
                new() { Command = auditdApply, Safety = auditdAnalysis.Safety, Analysis = auditdAnalysis }
            };

            var rollbackCommands = new List<RemediationCommand>
            {
                new() { Command = iptablesRollback, Safety = iptablesAnalysis.Safety, Analysis = iptablesAnalysis },
                new() { Command = auditdRollback, Safety = auditdAnalysis.Safety, Analysis = auditdAnalysis }
            };

            // M-2 Fix: Use iptables -C (exact rule check) instead of grep
            var verificationCommand = $"sudo {firewallTool} -C INPUT -s {attackerIp} -j DROP";

            var impactPreview = new RemediationImpactPreview
            {
                ExpectedImpact = $"Applying this step will block inbound traffic from {attackerIp} and enable tagged auditd connect telemetry for analyst correlation with that IP.",
                ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
                RollbackPath = iptablesRollback,
                RollbackPathKind = RemediationPreviewTextKind.Command,
                VerificationCommand = verificationCommand,
                IsVerificationCommand = true,
                VerificationKind = RemediationPreviewTextKind.Command
            };

            sections.Add(new RemediationSection
            {
                RuleId = "COUNTERMEASURE",
                FindingSummary = $"[Critical] Incident response: Beaconing → LateralMovement → PrivilegeEscalation on {compromisedHost}",
                RiskNote = "Active defense countermeasures. Review before deploying. Rollback commands are pre-generated. Auditd cannot filter connect syscalls by remote IP, so the audit rule tags connection telemetry for correlation while the firewall rule enforces the IP-specific block.",
                MitreTechniques = Array.Empty<MitreTechnique>(),
                Preconditions = new[] { "Root or sudo access required.", $"{firewallTool} and auditctl must be available.", "Auditd connect telemetry is host-wide and must be correlated with the attacker IP during review." },
                BackupCommands = Array.Empty<RemediationCommand>(),
                ApplyCommands = applyCommands,
                RollbackCommands = rollbackCommands,
                RollbackHints = Array.Empty<string>(),
                VerificationCommands = new List<RemediationCommand>
                {
                    new() { Command = verificationCommand, Safety = CommandSafety.ReadOnly, Analysis = new CommandAnalysis { RequiresSudo = true } }
                },
                HasExplicitRollbackGuidance = true,
                ImpactPreview = impactPreview,
                CountermeasureCommands = countermeasures
            });
        }

        return new RemediationPlan { Sections = sections };
    }

    private static bool IsCategory(Finding f, string category) =>
        string.Equals(f.Category, category, StringComparison.OrdinalIgnoreCase);

    private static bool TryExtractIpAddress(string target, out IPAddress address, out string normalized)
    {
        var trimmed = target.Trim();

        if (IPAddress.TryParse(trimmed.Trim(new[] { '[', ']' }), out address!))
        {
            normalized = address.ToString();
            return true;
        }

        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var endBracket = trimmed.IndexOf(']');
            if (endBracket > 1 && IPAddress.TryParse(trimmed[1..endBracket], out address!))
            {
                normalized = address.ToString();
                return true;
            }
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
            IPAddress.TryParse(uri.Host, out address!))
        {
            normalized = address.ToString();
            return true;
        }

        var colonCount = trimmed.Count(c => c == ':');
        if (colonCount == 1)
        {
            var hostPart = trimmed[..trimmed.IndexOf(':')];
            if (IPAddress.TryParse(hostPart, out address!))
            {
                normalized = address.ToString();
                return true;
            }
        }

        address = IPAddress.None;
        normalized = string.Empty;
        return false;
    }

    private static string BuildAuditKey(string attackerIp)
    {
        var safeIp = Regex.Replace(attackerIp, "[^A-Za-z0-9]", "_");
        return $"vulcanstrace_countermeasure_{safeIp}";
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
