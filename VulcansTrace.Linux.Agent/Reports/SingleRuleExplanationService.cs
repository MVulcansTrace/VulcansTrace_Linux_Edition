using System.Text;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class SingleRuleExplanationService
{
    private readonly ScannerCoordinator _scannerCoordinator;
    private readonly RuleEvaluationService _ruleEvaluationService;
    private readonly FindingAssemblyService _findingAssemblyService;
    private readonly AgentResultComposer _resultComposer;
    private readonly AgentAuditState _auditState;
    private readonly MachineRole _machineRole;

    public SingleRuleExplanationService(
        ScannerCoordinator scannerCoordinator,
        RuleEvaluationService ruleEvaluationService,
        FindingAssemblyService findingAssemblyService,
        AgentResultComposer resultComposer,
        AgentAuditState auditState,
        MachineRole machineRole)
    {
        _scannerCoordinator = scannerCoordinator ?? throw new ArgumentNullException(nameof(scannerCoordinator));
        _ruleEvaluationService = ruleEvaluationService ?? throw new ArgumentNullException(nameof(ruleEvaluationService));
        _findingAssemblyService = findingAssemblyService ?? throw new ArgumentNullException(nameof(findingAssemblyService));
        _resultComposer = resultComposer ?? throw new ArgumentNullException(nameof(resultComposer));
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _machineRole = machineRole;
    }

    public async Task<AgentResult> ExplainAsync(
        IRule rule,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(ruleHistory);
        ct.ThrowIfCancellationRequested();

        var scannerResult = await _scannerCoordinator.RunAsync(ct);
        var scanData = scannerResult.ScanData;
        var warnings = scannerResult.Warnings.ToList();
        var capabilityReport = _resultComposer.BuildCapabilityReport(scanData.Capabilities);
        var dataSourceCapabilities = _resultComposer.NormalizeCapabilities(scanData.Capabilities);

        var evaluatedRule = _ruleEvaluationService.EvaluateRule(rule, scanData, ct);
        warnings.AddRange(evaluatedRule.Warnings);

        if (evaluatedRule.DisabledByPolicy)
        {
            return new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                AgentFindings = Array.Empty<Finding>(),
                Warnings = warnings,
                UtcTimestamp = DateTime.UtcNow,
                Summary = $"Rule {rule.Id} is disabled by policy for {_machineRole}.",
                RuleResults = new[] { evaluatedRule.RuleResult },
                PassedCount = 1
            };
        }

        var result = evaluatedRule.RuleResult;
        var findingAssembly = _findingAssemblyService.Assemble(new[] { result }, applySuppressions: false);
        warnings.AddRange(findingAssembly.Warnings);
        var agentFindings = findingAssembly.AgentFindings;

        result = findingAssembly.RuleResults[0];
        var summary = result.Status == RuleStatus.Crashed
            ? $"Rule {rule.Id} could not be evaluated."
            : agentFindings.Count > 0
                ? BuildExplanationSummary(agentFindings[0], ruleHistory)
                : $"Rule {rule.Id} passed — no issue to explain.";

        var singleRuleResult = new AgentResult
        {
            Intent = AgentIntent.ExplainFinding,
            AgentFindings = agentFindings,
            Warnings = warnings,
            UtcTimestamp = DateTime.UtcNow,
            Summary = summary,
            RuleResults = new[] { result },
            PassedCount = result.Status == RuleStatus.Passed ? 1 : 0,
            FailedCount = result.Status == RuleStatus.Failed ? 1 : 0,
            CrashedCount = result.Status == RuleStatus.Crashed ? 1 : 0,
            CapabilityReport = capabilityReport,
            DataSourceCapabilities = dataSourceCapabilities
        };

        return singleRuleResult;
    }

    private static string BuildExplanationSummary(
        Finding finding,
        IReadOnlyDictionary<string, RuleMemoryEntry> ruleHistory)
    {
        var sb = new StringBuilder();
        sb.Append($"Explanation for [{finding.Severity}] {finding.ShortDescription}\n\n{finding.Details}");

        if (!string.IsNullOrWhiteSpace(finding.RuleId))
        {
            ruleHistory.TryGetValue(finding.RuleId, out var entry);
            AdaptiveExplanationBuilder.AppendAdaptiveSections(sb, finding, entry, DateTime.UtcNow);
        }

        return sb.ToString();
    }
}
