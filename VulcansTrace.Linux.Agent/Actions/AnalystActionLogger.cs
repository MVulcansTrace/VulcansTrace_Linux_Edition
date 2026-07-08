using VulcansTrace.Linux.Core.Logging;

namespace VulcansTrace.Linux.Agent.Actions;

/// <summary>
/// Records analyst actions to an <see cref="IAnalystActionStore"/> without ever throwing
/// over persistence failures. Each call captures the entry (including its UTC timestamp) on the
/// calling thread, then offloads the store append to the thread pool so callers that await on the
/// UI thread are not blocked by the synchronous file write. All writes are thread-safe through the
/// underlying store.
/// </summary>
public sealed class AnalystActionLogger
{
    private readonly IAnalystActionStore _store;
    private readonly ILogSink? _logSink;

    /// <summary>
    /// Initializes a new instance of the <see cref="AnalystActionLogger"/> class.
    /// </summary>
    /// <param name="store">The store that will durably persist analyst actions.</param>
    /// <param name="logSink">Optional sink for diagnostics when an action could not be recorded.</param>
    public AnalystActionLogger(IAnalystActionStore store, ILogSink? logSink = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _logSink = logSink;
    }

    /// <summary>
    /// Gets the underlying store.
    /// </summary>
    public IAnalystActionStore Store => _store;

    /// <summary>
    /// Records a generic analyst action. The entry and timestamp are captured synchronously; the
    /// store append runs on the thread pool. Exceptions never propagate to the caller.
    /// </summary>
    public Task LogAsync(
        string actor,
        string actionType,
        string? target = null,
        string? details = null,
        string? severity = null)
    {
        // Capture the timestamp on the calling thread so it reflects when the action happened,
        // not when the thread pool picks up the append.
        var entry = new AnalystActionEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            TimestampUtc = DateTime.UtcNow,
            Actor = actor,
            ActionType = actionType,
            Target = target,
            Details = details,
            Severity = severity
        };

        return Task.Run(() =>
        {
            try
            {
                _store.Append(entry);
            }
            catch (Exception ex)
            {
                // Logging must never crash the operation that triggered it, but surface the loss
                // through the diagnostics sink so it is not completely invisible.
                _logSink?.Write(LogLevel.Warning, $"Failed to record analyst action '{entry.ActionType}' for actor '{entry.Actor}': {ex.Message}", ex);
            }
        });
    }

    /// <summary>Records an audit run.</summary>
    public Task LogAuditAsync(string actor, string intent, string role, int findingsCount)
        => LogAsync(actor, AnalystActionType.AuditRan, intent, $"role={role}; findings={findingsCount}");

    /// <summary>Records a log diff comparison.</summary>
    public Task LogDiffAsync(string actor, string baselinePath, string incidentPath)
        => LogAsync(actor, AnalystActionType.AuditDiffRan, $"{baselinePath} -> {incidentPath}");

    /// <summary>Records that a finding was verified.</summary>
    public Task LogFindingVerifiedAsync(string actor, string ruleId)
        => LogAsync(actor, AnalystActionType.FindingVerified, ruleId);

    /// <summary>Records that a suppression was added.</summary>
    public Task LogSuppressionAsync(string actor, string ruleId, string target)
        => LogAsync(actor, AnalystActionType.SuppressionAdded, $"{ruleId} on {target}");

    /// <summary>Records that a remediation plan was exported.</summary>
    public Task LogRemediationAsync(string actor, string path)
        => LogAsync(actor, AnalystActionType.RemediationPlanExported, path);

    /// <summary>Records that a session report was exported.</summary>
    public Task LogSessionReportAsync(string actor, string path)
        => LogAsync(actor, AnalystActionType.SessionReportExported, path);

    /// <summary>Records that a signed evidence package was exported.</summary>
    public Task LogEvidenceExportedAsync(string actor, string path)
        => LogAsync(actor, AnalystActionType.EvidenceExported, path);

    /// <summary>Records that threat intelligence was exported.</summary>
    public Task LogThreatIntelExportedAsync(string actor, string format, string path)
        => LogAsync(actor, AnalystActionType.ThreatIntelExported, path, $"format={format}");

    /// <summary>Records that threat intelligence was imported.</summary>
    public Task LogThreatIntelImportedAsync(string actor, string format, int count)
        => LogAsync(actor, AnalystActionType.ThreatIntelImported, format, $"count={count}");

    /// <summary>Records that threat intelligence was cleared.</summary>
    public Task LogThreatIntelClearedAsync(string actor, int count)
        => LogAsync(actor, AnalystActionType.ThreatIntelCleared, details: $"count={count}");

    /// <summary>Records that a baseline was set.</summary>
    public Task LogBaselineSetAsync(string actor, string intent)
        => LogAsync(actor, AnalystActionType.BaselineSet, intent);

    /// <summary>Records that a drift check was run.</summary>
    public Task LogDriftCheckedAsync(string actor, string intent)
        => LogAsync(actor, AnalystActionType.DriftChecked, intent);

    /// <summary>Records that countermeasures were deployed.</summary>
    public Task LogCountermeasureDeployedAsync(string actor, string summary, bool? succeeded = null, int? failedCommands = null)
        => LogAsync(actor, AnalystActionType.CountermeasureDeployed, details: AppendOutcome(summary, succeeded, failedCommands));

    /// <summary>Records that a batch auto-fix was run.</summary>
    public Task LogBatchAutoFixAsync(string actor, int sectionCount, bool? succeeded = null, int? failedCommands = null)
        => LogAsync(actor, AnalystActionType.BatchAutoFixRan, details: AppendOutcome($"sections={sectionCount}", succeeded, failedCommands));

    /// <summary>Records that notification settings were changed.</summary>
    public Task LogNotificationSettingsChangedAsync(string actor, string? channel = null)
        => LogAsync(actor, AnalystActionType.NotificationSettingsChanged, target: channel, details: channel is null ? null : $"channel={channel}");

    /// <summary>Records that a rule policy was edited.</summary>
    public Task LogRulePolicyEditedAsync(string actor, string ruleId)
        => LogAsync(actor, AnalystActionType.RulePolicyEdited, ruleId);

    /// <summary>Records that a schedule was added.</summary>
    public Task LogScheduleAddedAsync(string actor, string scheduleId)
        => LogAsync(actor, AnalystActionType.ScheduleAdded, scheduleId);

    /// <summary>Records that a schedule was edited.</summary>
    public Task LogScheduleEditedAsync(string actor, string scheduleId)
        => LogAsync(actor, AnalystActionType.ScheduleEdited, scheduleId);

    /// <summary>Records that a schedule was deleted.</summary>
    public Task LogScheduleDeletedAsync(string actor, string scheduleId)
        => LogAsync(actor, AnalystActionType.ScheduleDeleted, scheduleId);

    /// <summary>Records that a schedule was enabled.</summary>
    public Task LogScheduleEnabledAsync(string actor, string scheduleId)
        => LogAsync(actor, AnalystActionType.ScheduleEnabled, scheduleId);

    /// <summary>Records that a schedule was disabled.</summary>
    public Task LogScheduleDisabledAsync(string actor, string scheduleId)
        => LogAsync(actor, AnalystActionType.ScheduleDisabled, scheduleId);

    private static string AppendOutcome(string details, bool? succeeded, int? failedCommands)
    {
        if (succeeded is { } success)
            details += $"; success={success}";
        if (failedCommands is { } failed)
            details += $"; failed={failed}";
        return details;
    }
}
