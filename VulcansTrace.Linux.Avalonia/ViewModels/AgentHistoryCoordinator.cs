using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

internal sealed class AgentHistoryCoordinator
{
    private readonly IAuditHistoryStore _historyStore;
    private readonly ObservableCollection<AuditHistoryEntry> _history;
    private readonly Action<string, bool> _addAgentMessage;
    private readonly Func<IEnumerable<AgentMessageViewModel>> _getMessages;
    private readonly Action _onHistoryChanged;

    public AgentHistoryCoordinator(
        IAuditHistoryStore historyStore,
        ObservableCollection<AuditHistoryEntry> history,
        Action<string, bool> addAgentMessage,
        Func<IEnumerable<AgentMessageViewModel>> getMessages,
        Action onHistoryChanged)
    {
        _historyStore = historyStore ?? throw new ArgumentNullException(nameof(historyStore));
        _history = history ?? throw new ArgumentNullException(nameof(history));
        _addAgentMessage = addAgentMessage ?? throw new ArgumentNullException(nameof(addAgentMessage));
        _getMessages = getMessages ?? throw new ArgumentNullException(nameof(getMessages));
        _onHistoryChanged = onHistoryChanged ?? throw new ArgumentNullException(nameof(onHistoryChanged));
    }

    public void AppendHistoryEntry(AgentResult result)
    {
        // The agent's result finalizer owns persisting audit history entries.
        // If the result already has a snapshot ID in the store, just refresh the UI.
        // Otherwise (e.g., in tests or legacy paths), build and append an entry here.
        if (!string.IsNullOrWhiteSpace(result.SnapshotId)
            && _historyStore.GetAll().Any(e => e.SnapshotId == result.SnapshotId))
        {
            RefreshFromStore();
            Dispatcher.UIThread.Post(AddHistoryPersistenceWarningIfAny);
            return;
        }

        var findings = result.AgentFindings;
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

        var entry = new AuditHistoryEntry
        {
            SnapshotId = Guid.NewGuid().ToString("N")[..8],
            TimestampUtc = result.UtcTimestamp,
            Intent = result.Intent,
            TotalFindings = findings.Count,
            CriticalCount = findings.Count(f => f.Severity == Severity.Critical),
            HighCount = findings.Count(f => f.Severity == Severity.High),
            MediumCount = findings.Count(f => f.Severity == Severity.Medium),
            LowCount = findings.Count(f => f.Severity == Severity.Low),
            InfoCount = findings.Count(f => f.Severity == Severity.Info),
            WarningCount = result.Warnings.Count,
            Exported = false,
            PassedCount = result.PassedCount,
            FailedCount = result.FailedCount,
            SuppressedCount = result.SuppressedCount,
            CrashedCount = result.CrashedCount,
            SnapshotFindings = snapshotFindings,
            Scorecard = result.Scorecard
        };

        _historyStore.Append(entry);
        RefreshFromStore();
        Dispatcher.UIThread.Post(AddHistoryPersistenceWarningIfAny);
    }

    public void RefreshFromStore()
    {
        _history.Clear();
        foreach (var entry in _historyStore.GetAll())
        {
            _history.Add(entry);
        }

        _onHistoryChanged();
    }

    public void LoadExisting()
    {
        _history.Clear();
        foreach (var entry in _historyStore.GetAll())
        {
            _history.Add(entry);
        }

        _onHistoryChanged();
    }

    public void MarkLatestExported()
    {
        if (_history.Count == 0)
            return;

        var updated = _history[0] with { Exported = true };
        _history[0] = updated;
        _historyStore.Update(updated);
        Dispatcher.UIThread.Post(AddHistoryPersistenceWarningIfAny);
    }

    public void ShowPersistenceWarningIfAny()
    {
        AddHistoryPersistenceWarningIfAny();
    }

    private void AddHistoryPersistenceWarningIfAny()
    {
        // Normalize once and reuse the same value for the duplicate check and the add. The presenter's
        // AddAgentMessage sanitizes every message, so comparing against the already-sanitized warning
        // keeps the dedup correct whether or not the backing store sanitizes its own getter.
        var warning = ErrorSanitizer.SanitizeOptional(_historyStore.PersistenceWarning);
        if (string.IsNullOrWhiteSpace(warning) || _getMessages().Any(message => message.Text == warning))
            return;

        _addAgentMessage(warning, true);
    }
}
