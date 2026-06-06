using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Baselines;

internal sealed class BaselineDriftService
{
    private readonly AgentAuditState _auditState;
    private readonly IBaselineStore? _baselineStore;
    private readonly Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> _runAudit;

    public BaselineDriftService(
        AgentAuditState auditState,
        IBaselineStore? baselineStore,
        Func<AgentIntent, string?, CancellationToken, Task<AgentResult>> runAudit)
    {
        _auditState = auditState ?? throw new ArgumentNullException(nameof(auditState));
        _baselineStore = baselineStore;
        _runAudit = runAudit ?? throw new ArgumentNullException(nameof(runAudit));
    }

    public Task<AgentResult> SetBaselineAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_auditState.LastResult == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Run an audit first, then say 'set baseline' to save it as a known-good snapshot.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        if (_baselineStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Baseline storage is not available. Baselines cannot be saved.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var name = !string.IsNullOrWhiteSpace(agentQuery.TargetReference)
            ? agentQuery.TargetReference
            : $"{_auditState.LastAuditIntent}-{_auditState.LastResult.UtcTimestamp:yyyyMMdd-HHmmss}";

        var baselineId = Guid.NewGuid().ToString("N");
        var findings = _auditState.LastResult.AgentFindings;
        var snapshotFindings = findings.Select(ToSnapshotFinding).ToList();

        var entry = new BaselineEntry
        {
            BaselineId = baselineId,
            Name = name,
            CreatedUtc = _auditState.LastResult.UtcTimestamp,
            Intent = _auditState.LastAuditIntent,
            TotalFindings = findings.Count,
            CriticalCount = findings.Count(f => f.Severity == Severity.Critical),
            HighCount = findings.Count(f => f.Severity == Severity.High),
            MediumCount = findings.Count(f => f.Severity == Severity.Medium),
            LowCount = findings.Count(f => f.Severity == Severity.Low),
            InfoCount = findings.Count(f => f.Severity == Severity.Info),
            IsActive = true,
            SnapshotFindings = snapshotFindings,
            OriginalFindings = findings.ToList()
        };

        _baselineStore.Save(entry);
        _baselineStore.SetActive(baselineId);

        var warnings = new List<string>();
        if (!string.IsNullOrWhiteSpace(_baselineStore.PersistenceWarning))
        {
            warnings.Add(_baselineStore.PersistenceWarning);
        }

        var summary = $"Baseline '{name}' saved for {_auditState.LastAuditIntent} with {findings.Count} finding(s).";
        if (findings.Count > 0)
        {
            summary += $" ({entry.CriticalCount} Critical, {entry.HighCount} High).";
        }

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.SetBaseline,
            Summary = summary,
            AgentFindings = Array.Empty<Finding>(),
            Warnings = warnings,
            Baseline = entry
        });
    }

    public Task<AgentResult> CheckDriftAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var intent = _auditState.LastResult?.Intent ?? AgentIntent.FullAudit;
        return RunDriftCheckAsync(intent, null, ct);
    }

    public Task<AgentResult> ShowBaselineAsync(AgentQuery agentQuery, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var intent = _auditState.LastResult?.Intent ?? AgentIntent.FullAudit;
        return ShowBaselineForIntentAsync(intent, ct);
    }

    public Task<AgentResult> ShowBaselineForIntentAsync(AgentIntent intent, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (_baselineStore == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "Baseline storage is not available.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var baseline = _baselineStore.GetActive(intent);

        if (baseline == null)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = $"No baseline set for {intent}. Run an audit and say 'set baseline' to create one.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        var findings = baseline.OriginalFindings.Count > 0
            ? baseline.OriginalFindings.Select(f => f with
            {
                Details = $"{f.Details}\n\n*(Part of baseline '{baseline.Name}' created {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC.)*"
            }).ToList()
            : baseline.SnapshotFindings.Select(sf => new Finding
            {
                RuleId = sf.RuleId,
                Category = string.IsNullOrEmpty(sf.Category) ? "Baseline" : sf.Category,
                Severity = ParseSeverityString(sf.Severity),
                Confidence = ParseConfidenceString(sf.Confidence),
                EvidenceSignals = sf.EvidenceSignals,
                SourceHost = "localhost",
                Target = sf.Target,
                ShortDescription = sf.ShortDescription,
                Details = $"Part of baseline '{baseline.Name}' created {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC.",
                TimeRangeStart = baseline.CreatedUtc,
                TimeRangeEnd = baseline.CreatedUtc
            }).ToList();

        var parts = new List<string>
        {
            $"**Baseline: {baseline.Name}**",
            $"Intent: {baseline.Intent}",
            $"Created: {baseline.CreatedUtc:yyyy-MM-dd HH:mm} UTC",
            $"Findings: {baseline.TotalFindings} ({baseline.CriticalCount} Critical, {baseline.HighCount} High, {baseline.MediumCount} Medium, {baseline.LowCount} Low, {baseline.InfoCount} Info)"
        };

        return Task.FromResult(new AgentResult
        {
            Intent = AgentIntent.ShowBaseline,
            Summary = string.Join("\n", parts),
            AgentFindings = findings,
            Warnings = Array.Empty<string>(),
            Baseline = baseline
        });
    }

    public async Task<AgentResult> RunDriftCheckAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
    {
        if (_baselineStore == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "Baseline storage is not available. Drift detection cannot run.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var baseline = _baselineStore.GetActive(intent);
        if (baseline == null)
        {
            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = $"No baseline set for {intent}. Run an audit and say 'set baseline' first.",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var savedLastResult = _auditState.LastResult;
        try
        {
            var liveResult = await _runAudit(intent, rawLog, ct);

            var currentEntry = new AuditHistoryEntry
            {
                SnapshotId = Guid.NewGuid().ToString("N")[..8],
                TimestampUtc = liveResult.UtcTimestamp,
                Intent = liveResult.Intent,
                TotalFindings = liveResult.AgentFindings.Count,
                SnapshotFindings = liveResult.AgentFindings.Select(ToSnapshotFinding).ToList()
            };

            var baselineHistoryEntry = ToAuditHistoryEntry(baseline);
            var diff = AuditDiffCalculator.Calculate(baselineHistoryEntry, currentEntry);
            var baselineDiff = new BaselineDiffResult
            {
                Baseline = baseline,
                Diff = diff
            };

            var actionableFindings = new List<Finding>();
            foreach (var df in diff.NewFindings.Concat(diff.WorsenedFindings.Select(w => new DiffFinding
            {
                RuleId = w.RuleId,
                Target = w.Target,
                Severity = w.NewSeverity,
                Confidence = w.NewConfidence,
                EvidenceSignals = w.EvidenceSignals,
                ShortDescription = w.ShortDescription,
                Fingerprint = w.Fingerprint
            })))
            {
                actionableFindings.Add(new Finding
                {
                    RuleId = df.RuleId,
                    Category = "Drift",
                    Severity = ParseSeverityString(df.Severity),
                    Confidence = ParseConfidenceString(df.Confidence),
                    EvidenceSignals = df.EvidenceSignals,
                    SourceHost = "localhost",
                    Target = df.Target,
                    ShortDescription = df.ShortDescription,
                    Details = "This finding is new or worsened compared to the baseline.",
                    TimeRangeStart = DateTime.UtcNow,
                    TimeRangeEnd = DateTime.UtcNow
                });
            }

            return new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = baselineDiff.Narrative,
                AgentFindings = actionableFindings,
                BaselineDiff = baselineDiff,
                Warnings = liveResult.Warnings,
                PassedCount = liveResult.PassedCount,
                FailedCount = liveResult.FailedCount,
                SuppressedCount = liveResult.SuppressedCount,
                CrashedCount = liveResult.CrashedCount,
                RuleResults = liveResult.RuleResults,
                CapabilityReport = liveResult.CapabilityReport
            };
        }
        finally
        {
            _auditState.RememberResult(savedLastResult);
        }
    }

    private static AuditSnapshotFinding ToSnapshotFinding(Finding f) => new()
    {
        RuleId = f.RuleId ?? $"__null-{f.Fingerprint ?? f.Id.ToString("N")}",
        Target = f.Target,
        Severity = f.Severity.ToString(),
        Confidence = f.Confidence.ToString(),
        EvidenceSignals = f.EvidenceSignals,
        ShortDescription = f.ShortDescription,
        Category = f.Category,
        Fingerprint = f.Fingerprint
    };

    private static AuditHistoryEntry ToAuditHistoryEntry(BaselineEntry baseline) => new()
    {
        SnapshotId = baseline.BaselineId,
        TimestampUtc = baseline.CreatedUtc,
        Intent = baseline.Intent,
        TotalFindings = baseline.TotalFindings,
        CriticalCount = baseline.CriticalCount,
        HighCount = baseline.HighCount,
        MediumCount = baseline.MediumCount,
        LowCount = baseline.LowCount,
        InfoCount = baseline.InfoCount,
        SnapshotFindings = baseline.SnapshotFindings
    };

    private static Severity ParseSeverityString(string severity) => severity.ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.Info
    };

    private static DetectionConfidence ParseConfidenceString(string? confidence) => confidence?.ToLowerInvariant() switch
    {
        "low" => DetectionConfidence.Low,
        "medium" => DetectionConfidence.Medium,
        "high" => DetectionConfidence.High,
        "confirmed" => DetectionConfidence.Confirmed,
        _ => DetectionConfidence.Unknown
    };
}
