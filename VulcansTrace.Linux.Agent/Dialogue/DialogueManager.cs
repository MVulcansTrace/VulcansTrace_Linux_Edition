using VulcansTrace.Linux.Agent.Query;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Orchestrates the conversation-aware resolution of a raw user query into
/// a structured <see cref="AgentQuery"/> using context, anaphora resolution,
/// and deterministic intent inference.
/// </summary>
public sealed class DialogueManager
{
    private readonly IQueryParser _queryParser;
    private readonly AnaphoraResolver _anaphoraResolver;
    private readonly IntentInferenceEngine _inferenceEngine;
    private readonly ResponseTemplateProvider _templateProvider;

    /// <summary>
    /// Creates a dialogue manager using the default keyword-based query parser.
    /// </summary>
    public DialogueManager()
        : this(new QueryParser(), new AnaphoraResolver(), new IntentInferenceEngine(), new ResponseTemplateProvider())
    {
    }

    /// <summary>
    /// Creates a dialogue manager with explicit resolver components.
    /// </summary>
    public DialogueManager(
        IQueryParser queryParser,
        AnaphoraResolver anaphoraResolver,
        IntentInferenceEngine inferenceEngine,
        ResponseTemplateProvider templateProvider)
    {
        _queryParser = queryParser ?? throw new ArgumentNullException(nameof(queryParser));
        _anaphoraResolver = anaphoraResolver ?? throw new ArgumentNullException(nameof(anaphoraResolver));
        _inferenceEngine = inferenceEngine ?? throw new ArgumentNullException(nameof(inferenceEngine));
        _templateProvider = templateProvider ?? throw new ArgumentNullException(nameof(templateProvider));
    }

    /// <summary>
    /// Resolves a raw user query into a structured, context-aware agent query.
    /// </summary>
    public AgentQuery Resolve(string query, DialogueContext context)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(context);

        // SINGLE-THREADED: AskAsync is currently single-threaded, so we snapshot
        // the entity frame under the context lock before handing it to the
        // resolver and inference engine. This makes the read contract explicit
        // and keeps the lock from giving a false sense of cross-thread safety.
        var entities = context.SnapshotEntities();

        var parsed = _queryParser.Parse(query);
        var resolution = _anaphoraResolver.Resolve(query, entities);
        var enriched = EnrichWithEntityFrame(parsed, entities);
        var (inferred, wasInferred) = _inferenceEngine.Infer(enriched, resolution, entities, query);

        // Anaphoric explain: "explain it" after an explanation should target
        // the focused finding even though the parser produced no reference.
        if (inferred.Intent == AgentIntent.ExplainFinding
            && string.IsNullOrWhiteSpace(inferred.TargetReference)
            && !string.IsNullOrWhiteSpace(resolution.RuleId))
        {
            inferred = inferred with { TargetReference = resolution.RuleId };
        }

        // Return the inferred query. If it is still ambiguous, the caller
        // (SecurityAgent) will use BuildClarificationPrompt to ask the user.
        return inferred;
    }

    /// <summary>
    /// Uses the extracted entity frame to resolve obvious intent/reference cases
    /// before the full inference engine runs.
    /// </summary>
    private static AgentQuery EnrichWithEntityFrame(AgentQuery parsed, EntityFrame entities)
    {
        var frame = parsed.Entities;
        if (!frame.HasEntities)
            return parsed;

        var intent = parsed.Intent;
        var target = parsed.TargetReference;

        // A single rule ID plus a remediation verb is a strong signal.
        // This override is topic-agnostic, so RemediationVerbKeywords must only
        // contain unambiguous verbs. Ambiguous words like "check" would pull
        // unrelated audit queries into remediation intents here.
        if (frame.RuleIds.Count == 1)
        {
            target ??= frame.RuleIds[0];

            if (intent == AgentIntent.Help && frame.RemediationVerb.HasValue)
            {
                intent = frame.RemediationVerb.Value;
            }
        }

        // A session ID plus verify/resume is a strong signal.
        if (!string.IsNullOrWhiteSpace(frame.SessionId))
        {
            target ??= frame.SessionId;

            if (intent == AgentIntent.Help && frame.RemediationVerb == AgentIntent.VerifyRemediation)
                intent = AgentIntent.VerifyRemediation;
            if (intent == AgentIntent.Help && frame.RemediationVerb == AgentIntent.ResumeRemediation)
                intent = AgentIntent.ResumeRemediation;
        }

        // If the parser was ambiguous, a single category can break the tie.
        if (parsed.IsAmbiguous && frame.Categories.Count == 1 && string.IsNullOrWhiteSpace(target))
        {
            target = frame.Categories[0];
        }

        if (intent == parsed.Intent && target == parsed.TargetReference)
            return parsed;

        return parsed with
        {
            Intent = intent,
            TargetReference = target,
            Confidence = Math.Max(parsed.Confidence, 0.8)
        };
    }

    /// <summary>
    /// Records a completed turn in the conversation context.
    /// </summary>
    public void PushTurn(DialogueContext context, string rawQuery, AgentQuery resolved)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(rawQuery);
        ArgumentNullException.ThrowIfNull(resolved);

        context.PushTurn(DialogueTurn.Now(rawQuery, resolved.Intent, resolved.TargetReference));
    }

    /// <summary>
    /// Builds a clarification prompt for an ambiguous query.
    /// </summary>
    public string BuildClarificationPrompt(AgentQuery query, DialogueContext context)
    {
        return _templateProvider.BuildClarificationPrompt(query, context.Entities);
    }
}
