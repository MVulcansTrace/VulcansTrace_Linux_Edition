using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class FindingAssemblyService
{
    private readonly IExplanationProvider _explanationProvider;
    private readonly ISuppressionStore? _suppressionStore;
    private readonly IHostIdentity _hostIdentity;

    public FindingAssemblyService(
        IExplanationProvider explanationProvider,
        ISuppressionStore? suppressionStore,
        IHostIdentity? hostIdentity = null)
    {
        _explanationProvider = explanationProvider ?? throw new ArgumentNullException(nameof(explanationProvider));
        _suppressionStore = suppressionStore;
        _hostIdentity = hostIdentity ?? new MachineHostIdentity();
    }

    public FindingAssemblyResult Assemble(IReadOnlyList<RuleResult> ruleResults, bool applySuppressions = true)
    {
        var agentFindings = new List<Finding>();
        var historyEntries = new List<(string RuleId, Finding Finding)>();
        var processedResults = new List<RuleResult>(ruleResults.Count);
        var warnings = new List<string>();
        var suppressedCount = 0;

        // Prune expired suppressions beyond the review retention window before checking.
        if (applySuppressions)
        {
            _suppressionStore?.PruneExpired();
        }

        foreach (var result in ruleResults)
        {
            if (result.Passed)
            {
                processedResults.Add(result);
                continue;
            }

            if (result.Status == RuleStatus.Crashed)
            {
                processedResults.Add(result);
                continue;
            }

            var finding = CreateFinding(result);

            if (applySuppressions && _suppressionStore != null && !string.IsNullOrEmpty(result.RuleId))
            {
                if (_suppressionStore.IsSuppressed(result.RuleId, result.Target, finding.Fingerprint))
                {
                    suppressedCount++;
                    processedResults.Add(result with { Status = RuleStatus.Suppressed });
                    continue;
                }
            }

            agentFindings.Add(finding);
            historyEntries.Add((result.RuleId, finding));
            processedResults.Add(result);
        }

        if (suppressedCount > 0)
        {
            warnings.Add($"{suppressedCount} finding(s) suppressed by user configuration.");
        }

        return new FindingAssemblyResult(agentFindings, historyEntries, processedResults, suppressedCount, warnings);
    }

    private Finding CreateFinding(RuleResult result)
    {
        var explanation = _explanationProvider.GetExplanation(result.ExplanationKey, result.Variables);
        var now = DateTime.UtcNow;

        var signals = new List<EvidenceSignal>
        {
            new EvidenceSignal
            {
                Name = $"Rule {result.RuleId} triggered",
                Source = "SecurityRule",
                Explanation = result.Description
            }
        };

        return new Finding
        {
            Category = result.Category,
            Severity = result.Severity,
            Confidence = FindingConfidenceCalculator.Calculate(signals),
            SourceHost = _hostIdentity.SourceHost,
            Target = result.Target,
            ShortDescription = result.Description,
            Details = explanation,
            TimeRangeStart = now,
            TimeRangeEnd = now,
            RuleId = result.RuleId,
            CisMappings = result.CisMappings,
            MitreTechniques = result.MitreTechniques,
            EvidenceSignals = signals,
            Variables = result.Variables
        };
    }
}
