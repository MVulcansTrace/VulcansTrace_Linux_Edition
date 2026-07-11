using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentResultStateCoordinatorTests
{
    [AvaloniaFact]
    public void SetLastResult_NonAuditResult_DoesNotEnableExportOrCompletedAudit()
    {
        var harness = new CoordinatorHarness();
        var result = new AgentResult { Intent = AgentIntent.Help, Summary = "help" };

        harness.State.SetLastResult(result);

        Assert.Same(result, harness.State.LastResult);
        Assert.False(harness.State.IsExportableAudit);
        Assert.False(harness.State.HasCompletedAudit);
        Assert.Equal(AgentIntent.FullAudit, harness.State.LastAuditIntent);
        Assert.Contains(nameof(AgentViewModel.LastResult), harness.PropertyChanges);
        Assert.Contains(nameof(AgentViewModel.CanExportAudit), harness.PropertyChanges);
        Assert.Equal(1, harness.RefreshCommandsCount);
        Assert.Empty(harness.History);
    }

    [AvaloniaFact]
    public void SetLastResult_AuditResult_EnablesExportButDoesNotAppendHistory()
    {
        var harness = new CoordinatorHarness();
        var result = new AgentResult { Intent = AgentIntent.SshCheck, Summary = "ssh" };

        harness.State.SetLastResult(result);

        Assert.True(harness.State.IsExportableAudit);
        Assert.False(harness.State.HasCompletedAudit);
        Assert.Equal(AgentIntent.FullAudit, harness.State.LastAuditIntent);
        Assert.Empty(harness.History);
        Assert.Null(harness.PublishedResult);
    }

    [AvaloniaTheory]
    [InlineData(AgentIntent.FilesystemAuditCheck)]
    [InlineData(AgentIntent.UserAccountCheck)]
    [InlineData(AgentIntent.LoggingAuditCheck)]
    [InlineData(AgentIntent.CronJobCheck)]
    [InlineData(AgentIntent.PackageVulnerabilityCheck)]
    [InlineData(AgentIntent.ContainerCheck)]
    [InlineData(AgentIntent.KubernetesCheck)]
    [InlineData(AgentIntent.ThreatIntelCheck)]
    [InlineData(AgentIntent.YaraCheck)]
    [InlineData(AgentIntent.ProcessRuntimeCheck)]
    public void IsAuditIntent_IncludesTypedAuditIntents(AgentIntent intent)
    {
        Assert.True(AgentResultStateCoordinator.IsAuditIntent(intent));
    }

    [AvaloniaFact]
    public void PublishAuditCompleted_UpdatesAuditStatePublishesAndAppendsHistory()
    {
        var harness = new CoordinatorHarness();
        var finding = CreateFinding("SSH-001", Severity.High);
        var result = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            Summary = "ssh",
            AgentFindings = new[] { finding },
            UtcTimestamp = new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc)
        };

        harness.State.PublishAuditCompleted(result);

        Assert.Same(result, harness.PublishedResult);
        Assert.True(harness.State.HasCompletedAudit);
        Assert.True(harness.State.IsExportableAudit);
        Assert.Equal(AgentIntent.SshCheck, harness.State.LastAuditIntent);
        Assert.Single(harness.History);
        Assert.Equal(AgentIntent.SshCheck, harness.History[0].Intent);
        Assert.Equal(1, harness.History[0].TotalFindings);
        Assert.Equal(1, harness.RefreshCommandsCount);
    }

    [AvaloniaFact]
    public void Reset_ClearsLastResultAndRestoresDefaultAuditState()
    {
        var harness = new CoordinatorHarness();
        harness.State.SetLastResult(new AgentResult { Intent = AgentIntent.SshCheck });
        harness.State.PublishAuditCompleted(new AgentResult { Intent = AgentIntent.SshCheck });

        harness.State.Reset();

        Assert.Null(harness.State.LastResult);
        Assert.False(harness.State.IsExportableAudit);
        Assert.False(harness.State.HasCompletedAudit);
        Assert.Equal(AgentIntent.FullAudit, harness.State.LastAuditIntent);
        Assert.Contains(nameof(AgentViewModel.LastResult), harness.PropertyChanges);
        Assert.Contains(nameof(AgentViewModel.CanExportAudit), harness.PropertyChanges);
    }

    [AvaloniaFact]
    public void SetLastResult_DriftResult_DoesNotOverwriteLastAuditIntent()
    {
        var harness = new CoordinatorHarness();
        harness.State.PublishAuditCompleted(new AgentResult { Intent = AgentIntent.SshCheck });

        harness.State.SetLastResult(new AgentResult { Intent = AgentIntent.CheckDrift });

        Assert.Equal(AgentIntent.SshCheck, harness.State.LastAuditIntent);
        Assert.False(harness.State.IsExportableAudit);
    }

    [AvaloniaTheory]
    [InlineData(AgentIntent.ShortVerdict)]
    [InlineData(AgentIntent.ShowFindings)]
    public void SetLastResult_CachedRendering_PreservesPriorAuditLastResult(AgentIntent cachedIntent)
    {
        var harness = new CoordinatorHarness();
        var audit = new AgentResult
        {
            Intent = AgentIntent.FullAudit,
            Summary = "audit",
            AgentFindings = new[] { CreateFinding("FW-001", Severity.High) }
        };
        harness.State.SetLastResult(audit);
        harness.State.PublishAuditCompleted(audit);

        // A cached rendering (short verdict or findings recap) presents existing audit data in a
        // different shape. It must not replace the prior audit, or export/batch-fix enablement
        // would flip off despite the audit still being the active context.
        var cached = new AgentResult { Intent = cachedIntent, Summary = "cached view", AgentFindings = Array.Empty<Finding>() };
        harness.State.SetLastResult(cached);

        Assert.Same(audit, harness.State.LastResult); // prior audit preserved
        Assert.True(harness.State.IsExportableAudit); // export still enabled
        Assert.True(harness.State.HasCompletedAudit);
        Assert.Same(audit, harness.PublishedResult); // only the real audit published; the cached view did not
        // Command state is still refreshed so dependents re-evaluate.
        Assert.Equal(3, harness.RefreshCommandsCount);
    }

    [AvaloniaTheory]
    [InlineData(AgentIntent.ShortVerdict)]
    [InlineData(AgentIntent.ShowFindings)]
    public void SetLastResult_CachedRendering_SeedsRehydratedAuditWhenCoordinatorIsEmpty(AgentIntent cachedIntent)
    {
        var harness = new CoordinatorHarness();
        var rehydratedAudit = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            Summary = "rehydrated audit",
            AgentFindings = new[] { CreateFinding("SSH-001", Severity.High) }
        };
        var cached = new AgentResult { Intent = cachedIntent, Summary = "cached view" };

        harness.State.SetLastResult(cached, rehydratedAudit);

        Assert.Same(rehydratedAudit, harness.State.LastResult);
        Assert.True(harness.State.IsExportableAudit);
        Assert.True(harness.State.HasCompletedAudit);
        Assert.Equal(AgentIntent.SshCheck, harness.State.LastAuditIntent);
        Assert.Null(harness.PublishedResult);
        Assert.Empty(harness.History);
    }

    private static Finding CreateFinding(string ruleId, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "SSH",
            Severity = severity,
            SourceHost = "localhost",
            Target = "sshd_config",
            ShortDescription = "SSH finding",
            Details = "Details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private sealed class CoordinatorHarness
    {
        private readonly ObservableCollection<AgentMessageViewModel> _messages = new();
        public ObservableCollection<AuditHistoryEntry> History { get; } = new();
        public List<string> PropertyChanges { get; } = new();
        public int RefreshCommandsCount { get; private set; }
        public AgentResult? PublishedResult { get; private set; }
        public AgentResultStateCoordinator State { get; }

        public CoordinatorHarness()
        {
            var historyCoordinator = new AgentHistoryCoordinator(
                new InMemoryAuditHistoryStore(),
                History,
                (text, isInfo) => _messages.Add(new AgentMessageViewModel { Text = text, IsInfo = isInfo }),
                () => _messages,
                () => { });

            State = new AgentResultStateCoordinator(
                historyCoordinator,
                PropertyChanges.Add,
                () => RefreshCommandsCount++,
                result => PublishedResult = result);
        }
    }
}
