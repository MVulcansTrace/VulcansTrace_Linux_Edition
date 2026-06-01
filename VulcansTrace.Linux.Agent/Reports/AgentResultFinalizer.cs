namespace VulcansTrace.Linux.Agent.Reports;

internal sealed class AgentResultFinalizer
{
    private readonly AgentAuditState _auditState;
    private readonly IAuditHistoryStore? _historyStore;
    private readonly IComplianceScorecardBuilder? _scorecardBuilder;
    private readonly IRiskScorecardBuilder _riskScorecardBuilder;

    public AgentResultFinalizer(
        AgentAuditState auditState,
        IAuditHistoryStore? historyStore,
        IComplianceScorecardBuilder? scorecardBuilder,
        IRiskScorecardBuilder? riskScorecardBuilder)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _historyStore = historyStore;
        _scorecardBuilder = scorecardBuilder;
        _riskScorecardBuilder = riskScorecardBuilder ?? new RiskScorecardBuilder();
    }

    public AgentResult FinalizeAudit(AgentResultFinalizationRequest request)
    {
        var timestamp = DateTime.UtcNow;
        var scorecard = _scorecardBuilder?.Build(request.RuleResults, _historyStore, timestamp);
        var riskScorecard = _riskScorecardBuilder.Build(request.AgentFindings, timestamp);

        var result = new AgentResult
        {
            Intent = request.Intent,
            AgentFindings = request.AgentFindings,
            LogAnalysisResult = request.LogAnalysisResult,
            Warnings = request.Warnings,
            UtcTimestamp = timestamp,
            Summary = request.Summary,
            RuleResults = request.RuleResults,
            PassedCount = request.PassedCount,
            FailedCount = request.FailedCount,
            SuppressedCount = request.SuppressedCount,
            CrashedCount = request.CrashedCount,
            CapabilityReport = request.CapabilityReport,
            Scorecard = scorecard,
            RiskScorecard = riskScorecard
        };

        _auditState.RememberAudit(result, request.Intent, request.HistoryEntries);
        return result;
    }
}
