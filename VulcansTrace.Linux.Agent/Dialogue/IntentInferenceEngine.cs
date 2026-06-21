using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Infers missing or ambiguous intents by combining the parsed query with
/// the prior conversation topic and tracked entities.
/// Fully deterministic — no ML or LLM involved.
/// </summary>
public sealed class IntentInferenceEngine
{
    /// <summary>
    /// Minimum confidence required to trust the raw parser output without inference.
    /// </summary>
    public const double InferenceThreshold = 0.35;

    /// <summary>
    /// Re-evaluates a parsed query in light of conversation context and
    /// anaphora resolution. Returns a potentially modified query and a flag
    /// indicating whether inference was applied.
    /// </summary>
    public (AgentQuery Query, bool Inferred) Infer(
        AgentQuery parsed,
        ReferenceResolution resolution,
        EntityFrame entities,
        string? rawQuery = null)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(resolution);
        ArgumentNullException.ThrowIfNull(entities);

        var priorTopic = entities.LastTopic;
        var raw = RawText(parsed, rawQuery);

        // If the parser was ambiguous, give deterministic category precedence a
        // chance before trusting the raw score. Truly mixed audit requests still
        // fall through as ambiguous and ask for clarification.
        if (parsed.IsAmbiguous && parsed.AlternativeIntents != null)
        {
            var disambiguated = Disambiguate(parsed, resolution, entities);
            if (disambiguated != null)
                return (disambiguated with { TargetReference = BuildTarget(parsed, resolution, entities), RawQuery = raw }, true);
        }

        // If the parser is already confident, only apply safe anaphora enrichment.
        if (parsed.Confidence >= InferenceThreshold && !resolution.HasAnaphora)
        {
            return (parsed, false);
        }

        // Remediation follow-ups.
        if (priorTopic == ConversationTopic.Remediation)
        {
            var remediationInferred = InferRemediationIntent(parsed, resolution, entities, raw);
            if (remediationInferred != null)
                return (remediationInferred with { TargetReference = BuildTarget(parsed, resolution, entities), RawQuery = raw }, true);
        }

        // Explanation → fix / remediate flow.
        if (priorTopic == ConversationTopic.Explanation && IsFixIntent(parsed, raw))
        {
            var target = BuildTarget(parsed, resolution, entities);
            if (LooksLikeGuidedRequest(parsed, raw))
                return (new AgentQuery(AgentIntent.StartRemediation, target, 1.0, RawQuery: raw), true);

            return (new AgentQuery(AgentIntent.FixFinding, target, 1.0, RawQuery: raw), true);
        }

        // Explanation → evidence / provenance flow.
        if (priorTopic == ConversationTopic.Explanation && LooksLikeEvidenceRequest(parsed, raw))
        {
            var target = BuildTarget(parsed, resolution, entities);
            return (new AgentQuery(AgentIntent.ShowEvidence, target, 1.0, RawQuery: raw), true);
        }

        // Audit/Explanation → filter category.
        if ((priorTopic == ConversationTopic.Audit || priorTopic == ConversationTopic.Explanation)
            && (LooksLikeFilterRequest(parsed, raw) || (resolution.HasAnaphora && !string.IsNullOrEmpty(resolution.Category))))
        {
            var category = resolution.Category ?? parsed.TargetReference;
            if (!string.IsNullOrEmpty(category))
                return (new AgentQuery(AgentIntent.FilterCategory, category, 1.0, RawQuery: raw), true);
        }

        // Any topic → explain critical.
        if (priorTopic != ConversationTopic.Help && LooksLikeCriticalExplanation(parsed, raw))
        {
            return (new AgentQuery(AgentIntent.ExplainCritical, resolution.Category, 1.0, RawQuery: raw), true);
        }

        // Low-confidence audit intent with a resolved category → run that category audit.
        if (parsed.Confidence < InferenceThreshold
            && !string.IsNullOrEmpty(resolution.Category)
            && IsAuditIntent(InferIntentFromCategory(resolution.Category)))
        {
            var auditIntent = InferIntentFromCategory(resolution.Category);
            return (new AgentQuery(auditIntent, null, 0.8, RawQuery: raw), true);
        }

        return (parsed, false);
    }

    private static AgentQuery? InferRemediationIntent(AgentQuery parsed, ReferenceResolution resolution, EntityFrame entities, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery);

        if (LooksLikeVerifyRequest(parsed, raw))
            return new AgentQuery(AgentIntent.VerifyRemediation, resolution.SessionId ?? entities.ActiveSessionId, 1.0, RawQuery: raw);

        if (LooksLikeListRequest(parsed, raw))
            return new AgentQuery(AgentIntent.ListRemediationSessions, null, 1.0, RawQuery: raw);

        if (LooksLikeResumeRequest(parsed, raw))
            return new AgentQuery(AgentIntent.ResumeRemediation, resolution.SessionId ?? entities.LastRemediationSessionId, 1.0, RawQuery: raw);

        if (LooksLikeNoteRequest(parsed, raw))
        {
            if (raw.Contains("step", StringComparison.OrdinalIgnoreCase))
                return new AgentQuery(AgentIntent.AddStepNote, BuildTarget(parsed, resolution, entities), 1.0, RawQuery: raw);
            return new AgentQuery(AgentIntent.AddSessionNote, resolution.SessionId ?? entities.ActiveSessionId, 1.0, RawQuery: raw);
        }

        if (LooksLikeFixRequest(parsed, raw) && resolution.RuleId != null)
        {
            if (LooksLikeGuidedRequest(parsed, raw))
                return new AgentQuery(AgentIntent.StartRemediation, resolution.RuleId, 1.0, RawQuery: raw);
            return new AgentQuery(AgentIntent.FixFinding, resolution.RuleId, 1.0, RawQuery: raw);
        }

        return null;
    }

    private static AgentQuery? Disambiguate(AgentQuery parsed, ReferenceResolution resolution, EntityFrame entities)
    {
        var priorTopic = entities.LastTopic;

        var alternatives = parsed.AlternativeIntents;
        if (alternatives == null)
            return null;

        var tiedIntents = new[] { parsed.Intent }.Concat(alternatives).ToHashSet();
        var categoryIntent = InferIntentFromCategory(resolution.Category);

        if (IsSpecificCategoryDisambiguation(resolution.Category, categoryIntent, tiedIntents))
            return new AgentQuery(categoryIntent, null, 1.0);

        // If prior topic was audit and alternatives are both audit intents,
        // prefer the one matching the resolved category.
        if (priorTopic == ConversationTopic.Audit && !string.IsNullOrEmpty(resolution.Category))
        {
            if (tiedIntents.Contains(categoryIntent))
                return new AgentQuery(categoryIntent, null, 1.0);
        }

        // If a rule ID is present, prefer explanation/fix intent over audit intent.
        if (!string.IsNullOrEmpty(resolution.RuleId)
            && (alternatives.Contains(AgentIntent.ExplainFinding)
                || alternatives.Contains(AgentIntent.FixFinding)))
        {
            return new AgentQuery(AgentIntent.ExplainFinding, resolution.RuleId, 1.0);
        }

        return null;
    }

    private static bool IsSpecificCategoryDisambiguation(
        string? category,
        AgentIntent categoryIntent,
        IReadOnlySet<AgentIntent> tiedIntents)
    {
        if (string.IsNullOrEmpty(category) || !tiedIntents.Contains(categoryIntent))
            return false;

        return category.ToLowerInvariant() switch
        {
            "ssh" or "sshd" => tiedIntents.Contains(AgentIntent.ServiceCheck),
            "filesystem" or "suid" or "sgid" or "world-writable" or "sticky" or "unowned" =>
                tiedIntents.Contains(AgentIntent.FilePermissionCheck)
                || tiedIntents.Contains(AgentIntent.UserAccountCheck),
            _ => false
        };
    }

    private static string? BuildTarget(AgentQuery parsed, ReferenceResolution resolution, EntityFrame entities)
    {
        // Explicitly resolved references take precedence.
        if (!string.IsNullOrEmpty(resolution.RuleId))
            return resolution.RuleId;
        if (!string.IsNullOrEmpty(resolution.Finding?.RuleId))
            return resolution.Finding.RuleId;
        if (!string.IsNullOrEmpty(resolution.SessionId))
            return resolution.SessionId;
        if (!string.IsNullOrEmpty(resolution.Category))
            return resolution.Category;

        // Parser target reference.
        if (!string.IsNullOrEmpty(parsed.TargetReference))
            return parsed.TargetReference;

        // Entity-frame fallbacks.
        if (!string.IsNullOrEmpty(entities.LastRuleId))
            return entities.LastRuleId;
        if (!string.IsNullOrEmpty(entities.LastFinding?.RuleId))
            return entities.LastFinding.RuleId;
        if (!string.IsNullOrEmpty(entities.ActiveSessionId))
            return entities.ActiveSessionId;
        if (!string.IsNullOrEmpty(entities.LastRemediationSessionId))
            return entities.LastRemediationSessionId;
        if (!string.IsNullOrEmpty(entities.LastCategory))
            return entities.LastCategory;

        return null;
    }

    private static string RawText(AgentQuery parsed, string? rawQuery)
        => rawQuery ?? parsed.RawQuery ?? parsed.TargetReference ?? string.Empty;

    private static bool ContainsWholeWord(string text, string word)
    {
        var index = 0;

        while ((index = text.IndexOf(word, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var before = index == 0 || !IsWordCharacter(text[index - 1]);
            var afterIndex = index + word.Length;
            var after = afterIndex >= text.Length || !IsWordCharacter(text[afterIndex]);
            if (before && after)
                return true;

            index += word.Length;
        }

        return false;
    }

    private static bool IsWordCharacter(char ch) => char.IsLetterOrDigit(ch) || ch == '_';

    private static bool LooksLikeFixRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "fix")
            || ContainsWholeWord(raw, "resolve")
            || ContainsWholeWord(raw, "remediate");
    }

    private static bool IsFixIntent(AgentQuery parsed, string? rawQuery)
    {
        return parsed.Intent == AgentIntent.FixFinding
            || parsed.Intent == AgentIntent.StartRemediation
            || LooksLikeFixRequest(parsed, rawQuery);
    }

    private static bool LooksLikeEvidenceRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return parsed.Intent == AgentIntent.ShowEvidence
            || ContainsWholeWord(raw, "prove")
            || ContainsWholeWord(raw, "evidence")
            || ContainsWholeWord(raw, "provenance")
            || ContainsWholeWord(raw, "sources")
            || (ContainsWholeWord(raw, "triggered") && ContainsWholeWord(raw, "what"))
            || (ContainsWholeWord(raw, "flagged") && ContainsWholeWord(raw, "why"));
    }

    private static bool LooksLikeGuidedRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "guided")
            || ContainsWholeWord(raw, "walk me through")
            || ContainsWholeWord(raw, "start remediation")
            || ContainsWholeWord(raw, "remediate");
    }

    private static bool LooksLikeFilterRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "only")
            || ContainsWholeWord(raw, "just show")
            || ContainsWholeWord(raw, "show me")
            || ContainsWholeWord(raw, "filter");
    }

    private static bool LooksLikeCriticalExplanation(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "why")
            && (ContainsWholeWord(raw, "critical")
                || ContainsWholeWord(raw, "severe")
                || ContainsWholeWord(raw, "high"));
    }

    private static bool LooksLikeVerifyRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "verify")
            || ContainsWholeWord(raw, "check it")
            || ContainsWholeWord(raw, "did it work")
            || ContainsWholeWord(raw, "did that work");
    }

    private static bool LooksLikeListRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "list")
            || ContainsWholeWord(raw, "show sessions")
            || ContainsWholeWord(raw, "my sessions");
    }

    private static bool LooksLikeResumeRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "resume")
            || ContainsWholeWord(raw, "continue")
            || ContainsWholeWord(raw, "open session")
            || ContainsWholeWord(raw, "open it");
    }

    private static bool LooksLikeNoteRequest(AgentQuery parsed, string? rawQuery)
    {
        var raw = RawText(parsed, rawQuery).ToLowerInvariant();
        return ContainsWholeWord(raw, "note")
            || ContainsWholeWord(raw, "comment");
    }

    private static bool IsAuditIntent(AgentIntent intent) => intent switch
    {
        AgentIntent.FullAudit
            or AgentIntent.FirewallCheck
            or AgentIntent.NetworkCheck
            or AgentIntent.ServiceCheck
            or AgentIntent.PortCheck
            or AgentIntent.SshCheck
            or AgentIntent.FilePermissionCheck
            or AgentIntent.FilesystemAuditCheck
            or AgentIntent.KernelCheck
            or AgentIntent.UserAccountCheck
            or AgentIntent.LoggingAuditCheck
            or AgentIntent.CronJobCheck
            or AgentIntent.PackageVulnerabilityCheck
            or AgentIntent.ContainerCheck
            or AgentIntent.KubernetesCheck
            or AgentIntent.ThreatIntelCheck
            or AgentIntent.YaraCheck
            or AgentIntent.ProcessRuntimeCheck => true,
        _ => false
    };

    private static AgentIntent InferIntentFromCategory(string? category) => category?.ToLowerInvariant() switch
    {
        "firewall" or "iptables" or "nftables" => AgentIntent.FirewallCheck,
        "network" => AgentIntent.NetworkCheck,
        "service" or "daemon" => AgentIntent.ServiceCheck,
        "port" or "listening" => AgentIntent.PortCheck,
        "ssh" or "sshd" => AgentIntent.SshCheck,
        "file" or "filepermission" or "permissions" => AgentIntent.FilePermissionCheck,
        "filesystem" or "suid" or "sgid" or "world-writable" or "sticky" or "unowned" => AgentIntent.FilesystemAuditCheck,
        "kernel" => AgentIntent.KernelCheck,
        "user" or "useraccount" or "account" or "password" or "shadow" or "uid" or "pam" => AgentIntent.UserAccountCheck,
        "logging" or "rsyslog" or "journald" or "audit" or "auditd" or "logrotate" or "forwarding" or "syslog" => AgentIntent.LoggingAuditCheck,
        "cron" or "crontab" or "scheduled" => AgentIntent.CronJobCheck,
        "packagevulnerability" or "package" or "cve" => AgentIntent.PackageVulnerabilityCheck,
        "container" or "docker" => AgentIntent.ContainerCheck,
        "kubernetes" or "k8s" or "pod" => AgentIntent.KubernetesCheck,
        "threatintel" or "threat-intel" or "ioc" => AgentIntent.ThreatIntelCheck,
        "yara" or "malware" => AgentIntent.YaraCheck,
        "processruntime" or "process" or "runtime" or "proc" or "ld_preload" or "injection" or "deleted binary" => AgentIntent.ProcessRuntimeCheck,
        _ => AgentIntent.Help
    };
}
