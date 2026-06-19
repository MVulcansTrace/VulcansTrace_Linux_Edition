using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Compliance;

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

        var snapshotId = AppendAuditHistory(request, timestamp, scorecard);

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
            RiskScorecard = riskScorecard,
            SnapshotId = snapshotId
        };

        _auditState.RememberAudit(result, request.Intent, request.HistoryEntries);
        return result;
    }

    private string? AppendAuditHistory(AgentResultFinalizationRequest request, DateTime timestamp, ComplianceScorecard? scorecard)
    {
        if (_historyStore == null)
            return null;

        var findings = request.AgentFindings;
        var snapshotFindings = findings.Select(f => new AuditSnapshotFinding
        {
            RuleId = f.RuleId ?? "",
            Target = f.Target,
            Severity = f.Severity.ToString(),
            Confidence = f.Confidence.ToString(),
            EvidenceSignals = f.EvidenceSignals,
            ShortDescription = f.ShortDescription,
            Category = f.Category,
            GroupedCount = f.GroupedCount,
            RepresentativeTargets = f.RepresentativeTargets,
            RiskDrivers = f.RiskDrivers,
            Fingerprint = f.Fingerprint
        }).ToList();

        var snapshotId = Guid.NewGuid().ToString("N")[..8];
        var entry = new AuditHistoryEntry
        {
            SnapshotId = snapshotId,
            TimestampUtc = timestamp,
            Intent = request.Intent,
            TotalFindings = findings.Count,
            CriticalCount = findings.Count(f => f.Severity == Severity.Critical),
            HighCount = findings.Count(f => f.Severity == Severity.High),
            MediumCount = findings.Count(f => f.Severity == Severity.Medium),
            LowCount = findings.Count(f => f.Severity == Severity.Low),
            InfoCount = findings.Count(f => f.Severity == Severity.Info),
            WarningCount = request.Warnings.Count,
            Exported = false,
            PassedCount = request.PassedCount,
            FailedCount = request.FailedCount,
            SuppressedCount = request.SuppressedCount,
            CrashedCount = request.CrashedCount,
            SnapshotFindings = snapshotFindings,
            CapabilityReport = request.CapabilityReport,
            RuleResults = request.RuleResults,
            Warnings = request.Warnings,
            LogAnalysisResult = request.LogAnalysisResult,
            Scorecard = scorecard
        };

        _historyStore.Append(entry);
        return snapshotId;
    }
}
