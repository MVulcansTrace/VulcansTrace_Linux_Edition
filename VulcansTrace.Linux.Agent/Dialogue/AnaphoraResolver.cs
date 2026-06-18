using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Resolves anaphoric references (pronouns, ordinals, demonstratives)
/// using the current <see cref="DialogueContext"/>.
/// </summary>
public sealed class AnaphoraResolver
{
    private readonly EntityExtractor _entityExtractor = new();

    /// <summary>
    /// Attempts to resolve references in the query against a snapshot of the
    /// conversation entities. Returns a <see cref="ReferenceResolution"/> describing
    /// what was found, even if no anaphora was present.
    /// </summary>
    public ReferenceResolution Resolve(string query, EntityFrame entities)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(entities);

        var extracted = _entityExtractor.ExtractAll(query);

        // If the query already has an explicit rule ID or session ID, no anaphora work is needed.
        if (!string.IsNullOrEmpty(extracted.RuleId) || !string.IsNullOrEmpty(extracted.SessionId))
        {
            return new ReferenceResolution(
                HasAnaphora: false,
                extracted.RuleId,
                extracted.SessionId,
                extracted.Category,
                extracted.Ordinal,
                null,
                null);
        }

        // Explicit category present — no need to resolve anaphora, but surface it.
        if (!string.IsNullOrEmpty(extracted.Category))
        {
            return new ReferenceResolution(
                HasAnaphora: extracted.HasAnaphora,
                RuleId: null,
                SessionId: null,
                extracted.Category,
                extracted.Ordinal,
                null,
                null);
        }

        // Explicit ordinal present without other context — try to resolve by ordinal.
        // Ordinals are references, but they are not anaphoric pronouns; do not
        // trigger intent inference based solely on an ordinal.
        if (extracted.Ordinal.HasValue)
        {
            var finding = ResolveOrdinal(extracted.Ordinal.Value, entities);
            if (finding == null)
                return ReferenceResolution.Empty;

            return new ReferenceResolution(
                HasAnaphora: false,
                finding.RuleId,
                null,
                finding.Category,
                extracted.Ordinal,
                finding,
                null);
        }

        // No anaphora marker and no explicit entity — nothing to resolve.
        if (!extracted.HasAnaphora)
        {
            return ReferenceResolution.Empty;
        }

        // Try to resolve the anaphora to the most relevant entity in context.
        var resolved = ResolveAnaphora(query, entities);
        return resolved with { HasAnaphora = true };
    }

    private static ReferenceResolution ResolveAnaphora(string query, EntityFrame entities)
    {
        var normalized = query.ToLowerInvariant();

        // Session references: "verify it", "that session", "the session we started".
        // Only treat pronouns as session references when the conversation is already
        // in a remediation context or a session actually exists.
        if (IsSessionReference(normalized, entities))
        {
            var sessionId = entities.ActiveSessionId ?? entities.LastRemediationSessionId;
            var session = entities.LastRemediationSession;
            return new ReferenceResolution(
                HasAnaphora: true,
                null,
                sessionId,
                null,
                null,
                null,
                session);
        }

        // Category references: "the SSH ones", "those container issues"
        var category = entities.LastCategory;
        if (!string.IsNullOrEmpty(category) && IsCategoryReference(normalized))
        {
            return new ReferenceResolution(
                HasAnaphora: true,
                null,
                null,
                category,
                null,
                null,
                null);
        }

        // Default: refer to the last focused finding/rule.
        // Do not leak the finding's category here; that prevents follow-ups like
        // "explain it again" from being misrouted to FilterCategory.
        var finding = entities.LastFinding;
        var ruleId = entities.LastRuleId ?? finding?.RuleId;
        return new ReferenceResolution(
            HasAnaphora: true,
            ruleId,
            null,
            null,
            null,
            finding,
            null);
    }

    private static Finding? ResolveOrdinal(int ordinal, EntityFrame entities)
    {
        var findings = entities.RankedFindings;
        if (ordinal < 1 || ordinal > findings.Count)
            return null;

        return findings[ordinal - 1];
    }

    private static bool IsSessionReference(string normalized, EntityFrame entities)
    {
        var hasSessionContext = entities.LastTopic == ConversationTopic.Remediation
            || !string.IsNullOrEmpty(entities.ActiveSessionId)
            || !string.IsNullOrEmpty(entities.LastRemediationSessionId)
            || entities.LastRemediationSession != null;

        if (!hasSessionContext)
            return false;

        return normalized.Contains("session", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("verify it", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("check it", StringComparison.OrdinalIgnoreCase)
            || (ContainsWholeWord(normalized, "it") && normalized.Contains("remediation", StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsWholeWord(string text, string word)
    {
        var index = text.IndexOf(word, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
            return false;

        var before = index == 0 || !char.IsLetterOrDigit(text[index - 1]);
        var after = index + word.Length >= text.Length || !char.IsLetterOrDigit(text[index + word.Length]);
        return before && after;
    }

    private static bool IsCategoryReference(string normalized)
    {
        return normalized.Contains("ones", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("issues", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("findings", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("those", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("these", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Result of resolving references from a user query against conversation context.
/// </summary>
public sealed record ReferenceResolution(
    bool HasAnaphora,
    string? RuleId,
    string? SessionId,
    string? Category,
    int? Ordinal,
    Finding? Finding,
    RemediationSession? Session)
{
    /// <summary>An empty resolution indicating no references were detected.</summary>
    public static ReferenceResolution Empty { get; } = new(false, null, null, null, null, null, null);
}
