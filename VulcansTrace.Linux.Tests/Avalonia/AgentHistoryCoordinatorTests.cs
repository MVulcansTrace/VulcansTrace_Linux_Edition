using System.Collections.ObjectModel;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Compliance;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class AgentHistoryCoordinatorTests
{
    [AvaloniaFact]
    public void LoadExisting_CopiesStoreEntriesAndNotifiesHistoryChanged()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        store.Append(CreateHistoryEntry("snap-older", DateTime.UtcNow.AddMinutes(-5)));
        store.Append(CreateHistoryEntry("snap-newer", DateTime.UtcNow));
        var harness = new CoordinatorHarness(store);

        harness.Coordinator.LoadExisting();

        Assert.Equal(2, harness.History.Count);
        Assert.Equal("snap-newer", harness.History[0].SnapshotId);
        Assert.Equal("snap-older", harness.History[1].SnapshotId);
        Assert.Equal(1, harness.HistoryChangedCount);
    }

    [AvaloniaFact]
    public void RefreshFromStore_ReplacesExistingCollectionAndNotifiesHistoryChanged()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var staleEntry = CreateHistoryEntry("stale", DateTime.UtcNow.AddDays(-1));
        var freshEntry = CreateHistoryEntry("fresh", DateTime.UtcNow);
        store.Append(freshEntry);
        var harness = new CoordinatorHarness(store);
        harness.History.Add(staleEntry);

        harness.Coordinator.RefreshFromStore();

        var entry = Assert.Single(harness.History);
        Assert.Equal("fresh", entry.SnapshotId);
        Assert.Equal(1, harness.HistoryChangedCount);
    }

    [AvaloniaFact]
    public void AppendHistoryEntry_BuildsSnapshotCountsAndRefreshesHistory()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var harness = new CoordinatorHarness(store);
        var scorecard = new ComplianceScorecard { OverallScore = 88, SummaryStatus = "Warn" };
        var timestamp = new DateTime(2026, 2, 3, 4, 5, 6, DateTimeKind.Utc);
        var result = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            UtcTimestamp = timestamp,
            AgentFindings = new[]
            {
                CreateFinding("FW-001", "Firewall", Severity.Critical, "Firewall disabled", "fp-fw"),
                CreateFinding("SSH-001", "SSH", Severity.High, "SSH exposed", "fp-ssh"),
                CreateFinding("LOG-001", "Logging", Severity.Medium, "Audit logs missing", "fp-log")
            },
            Warnings = new[] { "warning one", "warning two" },
            PassedCount = 7,
            FailedCount = 3,
            SuppressedCount = 1,
            CrashedCount = 2,
            Scorecard = scorecard
        };

        harness.Coordinator.AppendHistoryEntry(result);
        FlushDispatcher();

        var entry = Assert.Single(harness.History);
        Assert.Equal(timestamp, entry.TimestampUtc);
        Assert.Equal(AgentIntent.FullAudit, entry.Intent);
        Assert.Equal(3, entry.TotalFindings);
        Assert.Equal(1, entry.CriticalCount);
        Assert.Equal(1, entry.HighCount);
        Assert.Equal(1, entry.MediumCount);
        Assert.Equal(0, entry.LowCount);
        Assert.Equal(0, entry.InfoCount);
        Assert.Equal(2, entry.WarningCount);
        Assert.Equal(7, entry.PassedCount);
        Assert.Equal(3, entry.FailedCount);
        Assert.Equal(1, entry.SuppressedCount);
        Assert.Equal(2, entry.CrashedCount);
        Assert.False(entry.Exported);
        Assert.Same(scorecard, entry.Scorecard);
        Assert.Equal(1, harness.HistoryChangedCount);

        var snapshot = Assert.Single(entry.SnapshotFindings, f => f.RuleId == "FW-001");
        Assert.Equal("Firewall-target", snapshot.Target);
        Assert.Equal("Critical", snapshot.Severity);
        Assert.Equal("Confirmed", snapshot.Confidence);
        Assert.Equal("Firewall", snapshot.Category);
        Assert.Equal("Correlated behavior", Assert.Single(snapshot.EvidenceSignals).Name);
        Assert.Equal("Firewall disabled", snapshot.ShortDescription);
        Assert.Equal("fp-fw", snapshot.Fingerprint);
        Assert.Single(store.GetAll());
    }

    [AvaloniaFact]
    public void MarkLatestExported_UpdatesCollectionAndStore()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var entry = CreateHistoryEntry("snap-1", DateTime.UtcNow);
        store.Append(entry);
        var harness = new CoordinatorHarness(store);
        harness.Coordinator.LoadExisting();

        harness.Coordinator.MarkLatestExported();
        FlushDispatcher();

        Assert.True(harness.History[0].Exported);
        Assert.True(store.GetAll()[0].Exported);
    }

    [AvaloniaFact]
    public void MarkLatestExported_WithNoHistory_DoesNothing()
    {
        var harness = new CoordinatorHarness(new InMemoryAuditHistoryStore());

        harness.Coordinator.MarkLatestExported();
        FlushDispatcher();

        Assert.Empty(harness.History);
        Assert.Empty(harness.Messages);
    }

    [AvaloniaFact]
    public void ShowPersistenceWarningIfAny_AddsWarningOnce()
    {
        var harness = new CoordinatorHarness(new InMemoryAuditHistoryStore("History is in memory only."));

        harness.Coordinator.ShowPersistenceWarningIfAny();
        harness.Coordinator.ShowPersistenceWarningIfAny();

        var message = Assert.Single(harness.Messages);
        Assert.Equal("History is in memory only.", message.Text);
        Assert.True(message.IsInfo);
    }

    [AvaloniaFact]
    public void AppendHistoryEntry_PostsPersistenceWarningAndDeduplicates()
    {
        var harness = new CoordinatorHarness(new InMemoryAuditHistoryStore("History persistence unavailable."));

        harness.Coordinator.AppendHistoryEntry(new AgentResult
        {
            Intent = AgentIntent.FirewallCheck,
            UtcTimestamp = DateTime.UtcNow,
            AgentFindings = Array.Empty<Finding>()
        });
        FlushDispatcher();
        harness.Coordinator.AppendHistoryEntry(new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            UtcTimestamp = DateTime.UtcNow.AddMinutes(1),
            AgentFindings = Array.Empty<Finding>()
        });
        FlushDispatcher();

        Assert.Equal(2, harness.History.Count);
        Assert.Single(harness.Messages, m => m.Text == "History persistence unavailable.");
    }

    [AvaloniaFact]
    public void LoadExisting_CalledTwice_DoesNotDuplicateEntries()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        store.Append(CreateHistoryEntry("snap-1", DateTime.UtcNow));
        store.Append(CreateHistoryEntry("snap-2", DateTime.UtcNow.AddMinutes(-1)));
        var harness = new CoordinatorHarness(store);

        harness.Coordinator.LoadExisting();
        harness.Coordinator.LoadExisting();

        Assert.Equal(2, harness.History.Count);
    }

    [AvaloniaFact]
    public void LoadExisting_EmptyStore_ProducesEmptyHistory()
    {
        var harness = new CoordinatorHarness(new InMemoryAuditHistoryStore());

        harness.Coordinator.LoadExisting();

        Assert.Empty(harness.History);
        Assert.Equal(1, harness.HistoryChangedCount);
    }

    [AvaloniaFact]
    public void RefreshFromStore_WithEmptyStore_ClearsHistory()
    {
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var harness = new CoordinatorHarness(store);
        harness.History.Add(CreateHistoryEntry("stale", DateTime.UtcNow));

        harness.Coordinator.RefreshFromStore();

        Assert.Empty(harness.History);
        Assert.Equal(1, harness.HistoryChangedCount);
    }

    private static void FlushDispatcher() => Dispatcher.UIThread.RunJobs();

    private static AuditHistoryEntry CreateHistoryEntry(string snapshotId, DateTime timestamp) => new()
    {
        SnapshotId = snapshotId,
        TimestampUtc = timestamp,
        Intent = AgentIntent.FullAudit,
        TotalFindings = 1,
        SnapshotFindings = Array.Empty<AuditSnapshotFinding>()
    };

    private static Finding CreateFinding(
        string ruleId,
        string category,
        Severity severity,
        string shortDescription,
        string fingerprint)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = category,
            Severity = severity,
            Confidence = ruleId == "FW-001" ? DetectionConfidence.Confirmed : DetectionConfidence.Low,
            EvidenceSignals =
            [
                new EvidenceSignal { Name = ruleId == "FW-001" ? "Correlated behavior" : "Rule triggered", Source = "Behavior" }
            ],
            SourceHost = "localhost",
            Target = $"{category}-target",
            ShortDescription = shortDescription,
            Details = "Details",
            Fingerprint = fingerprint,
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private sealed class CoordinatorHarness
    {
        public ObservableCollection<AuditHistoryEntry> History { get; } = new();
        public ObservableCollection<AgentMessageViewModel> Messages { get; } = new();
        public int HistoryChangedCount { get; private set; }
        public AgentHistoryCoordinator Coordinator { get; }

        public CoordinatorHarness(IAuditHistoryStore store)
        {
            Coordinator = new AgentHistoryCoordinator(
                store,
                History,
                (text, isInfo) => Messages.Add(new AgentMessageViewModel { Text = text, IsInfo = isInfo }),
                () => Messages,
                () => HistoryChangedCount++);
        }
    }
}
