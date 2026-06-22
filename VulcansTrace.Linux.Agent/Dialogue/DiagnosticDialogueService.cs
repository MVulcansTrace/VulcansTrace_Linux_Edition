using System.Text;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Dialogue;

/// <summary>
/// Bounded, deterministic diagnostic dialogue for recurring findings.
/// Manages state transitions, question selection, answer matching, and response composition.
/// </summary>
public sealed class DiagnosticDialogueService
{
    private readonly DiagnosticQuestionBank _questionBank;
    private readonly RootCauseMatcher _rootCauseMatcher;

    /// <summary>
    /// Creates a service with default question bank and root-cause matcher.
    /// </summary>
    public DiagnosticDialogueService()
        : this(new DiagnosticQuestionBank(), new RootCauseMatcher())
    {
    }

    /// <summary>
    /// Creates a service with explicit components.
    /// </summary>
    public DiagnosticDialogueService(
        DiagnosticQuestionBank questionBank,
        RootCauseMatcher rootCauseMatcher)
    {
        _questionBank = questionBank ?? throw new ArgumentNullException(nameof(questionBank));
        _rootCauseMatcher = rootCauseMatcher ?? throw new ArgumentNullException(nameof(rootCauseMatcher));
    }

    /// <summary>
    /// Starts or continues a diagnostic investigation for a recurring finding.
    /// Returns a question if the finding qualifies and no question is pending;
    /// otherwise returns guidance directly.
    /// </summary>
    public Task<AgentResult> BeginInvestigationAsync(
        DialogueContext context,
        string ruleId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(ruleId);
        ct.ThrowIfCancellationRequested();

        var entities = context.Entities;
        var entry = GetRuleMemoryEntry(entities, ruleId);

        if (entry == null)
        {
            ResetDiagnosticState(entities);
            return Task.FromResult(BuildGuidanceResult(
                ruleId,
                $"I don't have any history for {ruleId}. Run an audit and, if the finding returns after a fix, ask me again."));
        }

        var closedCycles = entry.RemediationCycles.Where(c => c.IsClosed).ToList();
        if (closedCycles.Count < 2 && entry.Trend != RuleStatusTrend.Worsening)
        {
            ResetDiagnosticState(entities);
            return Task.FromResult(BuildGuidanceResult(
                ruleId,
                $"{ruleId} doesn't show a recurring pattern yet (only {closedCycles.Count} completed fix-and-return cycle(s)). If it comes back after a verified fix, ask me again."));
        }

        var question = _questionBank.GetQuestion(entry.Category, entry.Trend, closedCycles.Count);

        if (string.IsNullOrWhiteSpace(question))
        {
            ResetDiagnosticState(entities);
            return Task.FromResult(BuildGuidanceResult(
                ruleId,
                $"I don't have a targeted diagnostic question for {ruleId}, but this finding has returned before. {entry.Category}-specific guidance: look for config-management tools, reboot-time defaults, or base-image drift that may re-apply the insecure setting."));
        }

        entities.DiagnosticState = DialogueState.AwaitingDiagnosticAnswer;
        entities.PendingDiagnosticRuleId = ruleId;
        entities.PendingDiagnosticQuestion = question;

        var result = new AgentResult
        {
            Intent = AgentIntent.InvestigateRecurrence,
            Summary = $"{ruleId} has returned after being fixed. To find the root cause, I need to ask you one question.",
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>(),
            Narrative = new Narrative
            {
                Summary = $"{ruleId} has returned after being fixed. To find the root cause, I need to ask you one question.",
                KeyFindingsParagraph = $"**Question:** {question}",
                NextStepsParagraph = "Answer with what you know, or say 'I don't know' and I'll fall back to the category guidance.",
                SourceIds = new[] { ruleId }
            }
        };

        return Task.FromResult(result);
    }

    /// <summary>
    /// Continues the investigation with the user's answer and proposes a root cause.
    /// </summary>
    public Task<AgentResult> ContinueInvestigationAsync(
        DialogueContext context,
        string ruleId,
        string answer,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(ruleId);
        ArgumentException.ThrowIfNullOrEmpty(answer);
        ct.ThrowIfCancellationRequested();

        var entities = context.Entities;
        var match = _rootCauseMatcher.Match(answer, ruleId);

        var sb = new StringBuilder();
        sb.AppendLine(match.Explanation);

        var correlationText = BuildCorrelationText(ruleId, context);
        if (!string.IsNullOrWhiteSpace(correlationText))
        {
            sb.AppendLine();
            sb.AppendLine(correlationText);
        }

        entities.DiagnosticState = DialogueState.RootCauseProposed;
        entities.PendingDiagnosticRuleId = ruleId;
        entities.PendingDiagnosticQuestion = null;

        var sources = new List<string>(match.SourceIds);
        var result = new AgentResult
        {
            Intent = AgentIntent.AnswerDiagnosticQuestion,
            Summary = $"Root cause for {ruleId}:",
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>(),
            Narrative = new Narrative
            {
                Summary = $"Root cause for {ruleId}:",
                KeyFindingsParagraph = sb.ToString().Trim(),
                NextStepsParagraph = "If this root cause fits, fix it at the source (template, playbook, or image) and run a remediation. Ask me about another finding when you're ready.",
                SourceIds = sources
            }
        };

        return Task.FromResult(result);
    }

    /// <summary>
    /// Resets the diagnostic state machine to idle.
    /// </summary>
    public void ResetDiagnosticState(EntityFrame entities)
    {
        ArgumentNullException.ThrowIfNull(entities);
        entities.DiagnosticState = DialogueState.Idle;
        entities.PendingDiagnosticRuleId = null;
        entities.PendingDiagnosticQuestion = null;
    }

    private static RuleMemoryEntry? GetRuleMemoryEntry(EntityFrame entities, string ruleId)
    {
        if (entities.RuleHistory == null)
            return null;

        entities.RuleHistory.TryGetValue(ruleId, out var entry);
        return entry;
    }

    private static string? BuildCorrelationText(string ruleId, DialogueContext context)
    {
        var lastResult = context.LastResult;
        if (lastResult?.PostureCorrelations == null || lastResult.PostureCorrelations.Count == 0)
            return null;

        var relevant = lastResult.PostureCorrelations
            .Where(c =>
                string.Equals(c.RuleIdA, ruleId, StringComparison.OrdinalIgnoreCase)
                || string.Equals(c.RuleIdB, ruleId, StringComparison.OrdinalIgnoreCase)
                || c.MatchedFindingRuleIds.Any(r => string.Equals(r, ruleId, StringComparison.OrdinalIgnoreCase)))
            .Take(2)
            .ToList();

        if (relevant.Count == 0)
            return null;

        var sb = new StringBuilder();
        sb.Append("**Related findings:**");
        foreach (var correlation in relevant)
        {
            var otherRuleId = string.Equals(correlation.RuleIdA, ruleId, StringComparison.OrdinalIgnoreCase)
                ? correlation.RuleIdB
                : correlation.RuleIdA;
            sb.Append($" Your {ruleId} recurrence may be connected to {otherRuleId} ({correlation.Narrative}).");
        }

        return sb.ToString().Trim();
    }

    private static AgentResult BuildGuidanceResult(string ruleId, string message)
    {
        return new AgentResult
        {
            Intent = AgentIntent.InvestigateRecurrence,
            Summary = message,
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>(),
            Narrative = new Narrative
            {
                Summary = message,
                SourceIds = new[] { ruleId }
            }
        };
    }
}
