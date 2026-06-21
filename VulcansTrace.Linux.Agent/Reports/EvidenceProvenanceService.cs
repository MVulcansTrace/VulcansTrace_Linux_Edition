using System.Text;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

/// <summary>
/// Builds a conversational, deterministic evidence-chain (provenance) response for a finding.
/// Assembles only existing data: scanner sources, evidence signals, rule rationale,
/// CIS/MITRE mappings, cross-scanner validation, attack-chain membership, and rule memory.
/// </summary>
internal sealed class EvidenceProvenanceService
{
    private const string CrossScannerValidationSource = "CrossScannerValidation";

    private readonly AgentAuditState _auditState;
    private readonly RuleEvaluationService _ruleEvaluationService;
    private readonly SingleRuleExplanationService _singleRuleExplanationService;

    public EvidenceProvenanceService(
        AgentAuditState auditState,
        RuleEvaluationService ruleEvaluationService,
        SingleRuleExplanationService singleRuleExplanationService)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _ruleEvaluationService = ruleEvaluationService ?? throw new ArgumentNullException(nameof(ruleEvaluationService));
        _singleRuleExplanationService = singleRuleExplanationService ?? throw new ArgumentNullException(nameof(singleRuleExplanationService));
    }

    public async Task<AgentResult> BuildProvenanceAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var reference = ReferenceResolver.ResolveReference(agentQuery, _auditState.Entities);

        if (string.IsNullOrWhiteSpace(reference))
        {
            return new AgentResult
            {
                Intent = AgentIntent.ShowEvidence,
                Summary = "Please specify a finding to show evidence for (e.g., 'prove FW-002') or select one from the findings list.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>(),
                UtcTimestamp = DateTime.UtcNow
            };
        }

        var finding = _auditState.FindPreviousFinding(reference);
        var capabilities = _auditState.LastResult?.DataSourceCapabilities ?? Array.Empty<DataSourceCapability>();

        IRule? resolvedRule = null;
        if (finding == null)
        {
            resolvedRule = _ruleEvaluationService.FindRuleById(reference);
            if (resolvedRule != null)
            {
                var explained = await _singleRuleExplanationService.ExplainAsync(resolvedRule, _auditState.Entities.RuleHistory, ct).ConfigureAwait(false);
                finding = explained.AgentFindings.FirstOrDefault();
                // The fallback just re-ran the scanners for this rule; use the fresh capability
                // snapshot rather than the previous audit's (possibly unrelated or null) one.
                capabilities = explained.DataSourceCapabilities;

                if (finding == null)
                {
                    // The rule exists and is known, but it is currently passing — there is no
                    // active finding to assemble an evidence chain for. Say so explicitly rather
                    // than reporting a lookup failure.
                    return new AgentResult
                    {
                        Intent = AgentIntent.ShowEvidence,
                        Summary = $"**{resolvedRule.Id}** is currently passing, so there is no active finding to show evidence for. The rule and its CIS/MITRE mappings are known; rerun an audit after the condition changes to capture evidence.",
                        AgentFindings = Array.Empty<Finding>(),
                        Warnings = Array.Empty<string>(),
                        UtcTimestamp = DateTime.UtcNow
                    };
                }
            }
        }

        if (finding == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.ShowEvidence,
                Summary = $"I don't have a finding matching '{reference}'. Run an audit first, then ask me to show evidence for a specific finding (e.g., 'prove FW-002').",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>(),
                UtcTimestamp = DateTime.UtcNow
            };
        }

        var summary = BuildProvenanceSummary(finding, resolvedRule, capabilities);

        return new AgentResult
        {
            Intent = AgentIntent.ShowEvidence,
            AgentFindings = new List<Finding> { finding },
            Warnings = Array.Empty<string>(),
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary
        };
    }

    private string BuildProvenanceSummary(Finding finding, IRule? resolvedRule, IReadOnlyList<DataSourceCapability> capabilities)
    {
        var ruleId = finding.RuleId ?? "finding";
        var rule = !string.IsNullOrWhiteSpace(finding.RuleId)
            ? (_ruleEvaluationService.FindRuleById(finding.RuleId) ?? resolvedRule)
            : resolvedRule;

        var sb = new StringBuilder();
        sb.AppendLine($"**{ruleId}** — {finding.ShortDescription}");
        if (!string.IsNullOrWhiteSpace(finding.Target) && !finding.Target.Equals(finding.ShortDescription, StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine($"Target: {Code(finding.Target)}");
        }
        sb.AppendLine();

        AppendDetectionSource(sb, finding, rule, capabilities);
        AppendRawEvidence(sb, finding);
        AppendRuleEvaluation(sb, finding);
        AppendComplianceContext(sb, finding);
        AppendThreatContext(sb, finding);
        AppendAttackChainMembership(sb, finding);
        AppendHistory(sb, finding);

        return sb.ToString().Trim();
    }

    private void AppendDetectionSource(StringBuilder sb, Finding finding, IRule? rule, IReadOnlyList<DataSourceCapability> capabilities)
    {
        var scannerName = GetScannerDisplayName(finding.Category);
        sb.AppendLine("**Detection source**");
        sb.Append($"Detected by the **{scannerName}** scanner");

        var dataSources = rule?.SupportedDataSources ?? Array.Empty<string>();

        if (dataSources.Count > 0)
        {
            var sourceParts = new List<string>();
            foreach (var dataSource in dataSources)
            {
                var capability = FindMatchingCapability(dataSource, capabilities);
                var statusLabel = capability?.Status switch
                {
                    CapabilityStatus.Available => "Available",
                    CapabilityStatus.PermissionLimited => "permission-limited",
                    CapabilityStatus.Unavailable => "unavailable",
                    _ => "unknown"
                };

                var command = capability?.Command ?? dataSource;
                sourceParts.Add($"{Code(command)} — {statusLabel}");
            }

            sb.Append(" via ");
            sb.Append(string.Join(", ", sourceParts));
        }

        sb.AppendLine(".");
        sb.AppendLine();
    }

    /// <summary>
    /// Finds the capability that best describes a rule's declared data source. Matching prefers
    /// exact equality, then first-token equality, then substring containment; ties are broken by
    /// the longer (more specific) source name so short tokens like "ss" never shadow "sshd_config"
    /// or "passwd". Returns null when no capability matches.
    /// </summary>
    private static DataSourceCapability? FindMatchingCapability(string dataSource, IReadOnlyList<DataSourceCapability> capabilities)
    {
        if (string.IsNullOrWhiteSpace(dataSource))
            return null;

        var firstToken = dataSource.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? dataSource;

        DataSourceCapability? best = null;
        var bestPriority = 0;
        var bestNameLength = 0;

        foreach (var cap in capabilities)
        {
            if (string.IsNullOrWhiteSpace(cap.SourceName))
                continue;

            var priority = MatchPriority(dataSource, firstToken, cap);
            if (priority == 0)
                continue;

            if (priority > bestPriority || (priority == bestPriority && cap.SourceName.Length > bestNameLength))
            {
                best = cap;
                bestPriority = priority;
                bestNameLength = cap.SourceName.Length;
            }
        }

        return best;
    }

    private static int MatchPriority(string dataSource, string firstToken, DataSourceCapability cap)
    {
        var name = cap.SourceName;
        var command = cap.Command;

        // Priority 3: exact equality on the whole data source string.
        if (dataSource.Equals(name, StringComparison.OrdinalIgnoreCase))
            return 3;
        if (!string.IsNullOrWhiteSpace(command) && dataSource.Equals(command, StringComparison.OrdinalIgnoreCase))
            return 3;

        // Priority 2: the data source's first whitespace token matches the source name or the
        // command's first token (e.g. "iptables -L -n -v" -> "iptables").
        var commandFirstToken = string.IsNullOrWhiteSpace(command)
            ? null
            : command.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

        if (firstToken.Equals(name, StringComparison.OrdinalIgnoreCase))
            return 2;
        if (commandFirstToken != null && firstToken.Equals(commandFirstToken, StringComparison.OrdinalIgnoreCase))
            return 2;

        // Priority 1: substring containment. The caller breaks ties on this tier by longest name,
        // so "sshd_config" wins over "ss".
        if (dataSource.Contains(name, StringComparison.OrdinalIgnoreCase))
            return 1;
        if (!string.IsNullOrWhiteSpace(command) && dataSource.Contains(command, StringComparison.OrdinalIgnoreCase))
            return 1;

        return 0;
    }

    private static void AppendRawEvidence(StringBuilder sb, Finding finding)
    {
        sb.AppendLine("**Raw evidence**");

        if (finding.EvidenceSignals.Count == 0)
        {
            sb.AppendLine("No raw evidence signals were captured for this finding.");
            sb.AppendLine();
            return;
        }

        foreach (var signal in finding.EvidenceSignals)
        {
            string label;
            string body;
            if (signal.Source == CrossScannerValidationSource)
            {
                var contradicts = signal.Name.StartsWith("Contradicts:", StringComparison.OrdinalIgnoreCase);
                label = contradicts ? "Cross-scanner validation contradicts" : "Cross-scanner validation supports";
                // The verdict prefix is re-expressed as prose above; emit the inner signal name
                // (everything after "Supports: "/"Contradicts: ") when present.
                body = StripVerdictPrefix(signal.Name);
            }
            else
            {
                label = string.IsNullOrWhiteSpace(signal.Source) ? "Signal" : signal.Source;
                body = signal.Name;
            }

            if (!string.IsNullOrWhiteSpace(body))
                sb.AppendLine($"- **{label}:** {body} — {signal.Explanation}");
            else
                sb.AppendLine($"- **{label}:** {signal.Explanation}");
        }

        sb.AppendLine();
    }

    private static string StripVerdictPrefix(string name)
    {
        var colon = name.IndexOf(':');
        if (colon < 0 || colon == name.Length - 1)
            return string.Empty;
        return name[(colon + 1)..].Trim();
    }

    private static void AppendRuleEvaluation(StringBuilder sb, Finding finding)
    {
        sb.AppendLine("**Rule evaluation**");
        sb.AppendLine($"Severity: **{finding.Severity}**. Confidence: **{finding.Confidence}**.");
        if (!string.IsNullOrWhiteSpace(finding.Details))
        {
            sb.AppendLine(SanitizeInline(finding.Details));
        }
        sb.AppendLine();
    }

    private static void AppendComplianceContext(StringBuilder sb, Finding finding)
    {
        if (finding.CisMappings.Count == 0)
            return;

        sb.AppendLine("**Compliance context**");
        foreach (var cis in finding.CisMappings)
        {
            sb.Append($"- {cis.ControlId} — {cis.ControlName}");
            if (!string.IsNullOrWhiteSpace(cis.BenchmarkReference))
            {
                sb.Append($" ({cis.BenchmarkReference})");
            }
            sb.AppendLine();
        }
        sb.AppendLine();
    }

    private static void AppendThreatContext(StringBuilder sb, Finding finding)
    {
        if (finding.MitreTechniques.Count == 0)
            return;

        sb.AppendLine("**Threat context**");
        var techniqueTexts = finding.MitreTechniques
            .Select(t => $"{t.TechniqueId} ({t.TechniqueName})")
            .ToList();
        sb.AppendLine("MITRE ATT&CK " + string.Join(", ", techniqueTexts) + ".");
        sb.AppendLine();
    }

    private void AppendAttackChainMembership(StringBuilder sb, Finding finding)
    {
        var ruleId = finding.RuleId;
        if (string.IsNullOrWhiteSpace(ruleId) || _auditState.LastResult == null)
            return;

        var chains = _auditState.LastResult.AttackChains
            .Where(c => c.RuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase))
            .Where(c => c.Links.Any(l => !string.IsNullOrWhiteSpace(l.RuleId)))
            .ToList();

        if (chains.Count == 0)
            return;

        sb.AppendLine("**Attack chain membership**");
        sb.AppendLine($"This finding appears in {chains.Count} attack chain(s):");
        foreach (var chain in chains)
        {
            var links = chain.Links
                .Where(l => !string.IsNullOrWhiteSpace(l.RuleId))
                .Select(l => l.RuleId);
            sb.AppendLine($"- {string.Join(" → ", links)}");
        }
        sb.AppendLine();
    }

    private void AppendHistory(StringBuilder sb, Finding finding)
    {
        var ruleId = finding.RuleId;
        if (string.IsNullOrWhiteSpace(ruleId))
            return;

        _auditState.Entities.RuleHistory.TryGetValue(ruleId, out var entry);
        if (entry == null)
            return;

        sb.AppendLine("**History**");

        var parts = new List<string>();

        if (entry.FirstSeenUtc != default)
        {
            var elapsed = DateTime.UtcNow - entry.FirstSeenUtc;
            parts.Add($"first detected {FormatElapsed(elapsed)} ago");
        }

        if (entry.SeverityHistory.Count > 0)
        {
            parts.Add($"present in {entry.SeverityHistory.Count} audit snapshot(s)");
        }

        if (entry.Trend != RuleStatusTrend.New)
        {
            parts.Add($"trend is **{entry.Trend}**");
        }

        if (entry.LastVerifiedFixedUtc.HasValue)
        {
            var elapsed = DateTime.UtcNow - entry.LastVerifiedFixedUtc.Value;
            parts.Add($"last verified fixed {FormatElapsed(elapsed)} ago");
        }

        if (parts.Count == 0)
        {
            parts.Add("No detailed history is available for this rule.");
        }

        sb.AppendLine(string.Join("; ", parts) + ".");
    }

    private static string FormatElapsed(TimeSpan elapsed)
    {
        // Clock skew can leave a recorded timestamp slightly in the future; clamp so we never
        // render a misleading negative span.
        if (elapsed <= TimeSpan.Zero)
            return "less than a minute";

        if (elapsed.TotalDays >= 1)
            return $"{(int)elapsed.TotalDays} day{(elapsed.TotalDays >= 2 ? "s" : "")}";
        if (elapsed.TotalHours >= 1)
            return $"{(int)elapsed.TotalHours} hour{(elapsed.TotalHours >= 2 ? "s" : "")}";
        if (elapsed.TotalMinutes >= 1)
            return $"{(int)elapsed.TotalMinutes} minute{(elapsed.TotalMinutes >= 2 ? "s" : "")}";
        return "less than a minute";
    }

    private static string GetScannerDisplayName(string category)
    {
        return category?.ToLowerInvariant() switch
        {
            "firewall" => "Firewall",
            "network" => "Network",
            "service" => "Service",
            "port" => "Port",
            "ssh" => "SSH config",
            "filepermission" => "File permission",
            "filesystemaudit" => "Filesystem audit",
            "kernel" => "Kernel hardening",
            "useraccount" => "User account",
            "logging" => "Logging audit",
            "cronjob" => "Cron job",
            "packagevulnerability" => "Package vulnerability",
            "container" => "Container",
            "kubernetes" => "Kubernetes",
            "threatintel" => "Threat intel",
            "yara" => "YARA",
            "processruntime" => "Process runtime",
            _ => category ?? "Unknown"
        };
    }

    /// <summary>
    /// Wraps text in an inline-code span. If the content contains a backtick, uses Markdown's
    /// double-backtick delimiter with surrounding spaces so the literal backtick is preserved
    /// and the span cannot be closed prematurely (e.g. `` echo `date` ``).
    /// </summary>
    private static string Code(string? text)
    {
        var content = text ?? string.Empty;
        if (string.IsNullOrEmpty(content))
            return "``";

        // Content that itself contains a backtick must be wrapped in a longer backtick run and
        // padded so internal backticks cannot be misread as part of the closing delimiter.
        if (content.Contains('`'))
            return $"`` {content} ``";

        return $"`{content}`";
    }

    /// <summary>
    /// Replaces backticks in free-form prose so they cannot accidentally open a stray code span.
    /// This is acceptable for narrative/details text because backticks are rare and an apostrophe
    /// preserves readability; use <see cref="Code"/> for actual command/identifier code spans.
    /// </summary>
    private static string SanitizeInline(string? text)
        => (text ?? string.Empty).Replace("`", "'");
}
