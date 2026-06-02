using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class FindingExplanationService
{
    private readonly AgentAuditState _auditState;
    private readonly RuleEvaluationService _ruleEvaluationService;
    private readonly IExplanationProvider _explanationProvider;
    private readonly SingleRuleExplanationService _singleRuleExplanationService;

    public FindingExplanationService(
        AgentAuditState auditState,
        RuleEvaluationService ruleEvaluationService,
        IExplanationProvider explanationProvider,
        SingleRuleExplanationService singleRuleExplanationService)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _ruleEvaluationService = ruleEvaluationService ?? throw new ArgumentNullException(nameof(ruleEvaluationService));
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _singleRuleExplanationService = singleRuleExplanationService ?? throw new ArgumentNullException(nameof(singleRuleExplanationService));
    }

    public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var structured = _explanationProvider.ParseStructuredFromText(finding.Details);
        var summary = BuildStructuredSummary(finding, structured);

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = new List<Finding> { finding },
            Warnings = Array.Empty<string>(),
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary
        });
    }

    public async Task<AgentResult> HandleExplainFindingAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!string.IsNullOrWhiteSpace(agentQuery.TargetReference))
        {
            var reference = agentQuery.TargetReference;
            var matched = _auditState.FindPreviousFinding(reference);

            if (matched != null)
            {
                return await ExplainFindingAsync(matched, ct);
            }

            var matchingRule = _ruleEvaluationService.FindRuleById(reference);

            if (matchingRule != null)
            {
                return await _singleRuleExplanationService.ExplainAsync(matchingRule, ct);
            }

            return new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = $"I don't have a finding matching '{reference}'. Run an audit first, then ask me to explain a specific finding (e.g., 'explain FW-001').",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        return new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            Summary = "Please specify a finding to explain (e.g., 'explain FW-001') or select one from the findings list.",
            AgentFindings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>()
        };
    }

    private static string BuildStructuredSummary(Finding finding, StructuredExplanation structured)
    {
        var parts = new List<string>
        {
            $"**[{finding.RuleId ?? "finding"}] {finding.ShortDescription}**",
            "",
            "**What was found**",
            string.IsNullOrEmpty(structured.WhatWasFound) ? finding.ShortDescription : structured.WhatWasFound,
            "",
            "**Why it matters**",
            string.IsNullOrEmpty(structured.WhyItMatters) ? "See details." : structured.WhyItMatters,
        };

        if (!string.IsNullOrEmpty(structured.HowToVerify))
        {
            parts.Add("");
            parts.Add("**How to verify**");
            parts.Add(structured.HowToVerify);
        }

        if (!string.IsNullOrEmpty(structured.SuggestedNextAction))
        {
            parts.Add("");
            parts.Add("**Suggested next action**");
            parts.Add(structured.SuggestedNextAction);
        }

        if (!string.IsNullOrEmpty(structured.Confidence))
        {
            parts.Add("");
            parts.Add($"**Confidence:** {structured.Confidence}");
        }

        if (!string.IsNullOrEmpty(structured.Caveats))
        {
            parts.Add($"**Caveats:** {structured.Caveats}");
        }

        return string.Join("\n", parts);
    }
}
