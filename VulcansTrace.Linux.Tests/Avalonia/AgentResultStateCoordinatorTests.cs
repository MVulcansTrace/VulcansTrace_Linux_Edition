using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentResultStateCoordinatorTests
{
    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
    public void SetLastResult_DriftResult_DoesNotOverwriteLastAuditIntent()
    {
        var harness = new CoordinatorHarness();
        harness.State.PublishAuditCompleted(new AgentResult { Intent = AgentIntent.SshCheck });

        harness.State.SetLastResult(new AgentResult { Intent = AgentIntent.CheckDrift });

        Assert.Equal(AgentIntent.SshCheck, harness.State.LastAuditIntent);
        Assert.False(harness.State.IsExportableAudit);
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
