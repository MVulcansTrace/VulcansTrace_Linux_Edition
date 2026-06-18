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
        var (inferred, wasInferred) = _inferenceEngine.Infer(parsed, resolution, entities, query);

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
