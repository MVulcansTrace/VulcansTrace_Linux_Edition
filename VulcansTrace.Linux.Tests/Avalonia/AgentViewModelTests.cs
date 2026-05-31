using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentViewModelTests
{
    [Fact]
    public void NotifySelectedFindingChanged_RefreshesExplainSelectedState()
    {
        var selected = CreateFinding();
        var hasSelection = false;
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore())
        {
            SelectedFindingProvider = () => hasSelection ? selected : null
        };

        Assert.False(vm.CanExplainSelected);
        Assert.False(vm.ExplainSelectedCommand.CanExecute(null));

        hasSelection = true;
        vm.NotifySelectedFindingChanged();

        Assert.True(vm.CanExplainSelected);
        Assert.True(vm.ExplainSelectedCommand.CanExecute(null));

        hasSelection = false;
        vm.NotifySelectedFindingChanged();

        Assert.False(vm.CanExplainSelected);
        Assert.False(vm.ExplainSelectedCommand.CanExecute(null));
    }

    [Fact]
    public void SelectedChatCategoryFilter_AllCategories_KeepsFindingMessagesVisible()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore());
        var firewallMessage = new AgentMessageViewModel
        {
            Text = "Firewall finding",
            Category = "Firewall",
            Severity = Severity.High
        };
        var networkMessage = new AgentMessageViewModel
        {
            Text = "Network finding",
            Category = "Network",
            Severity = Severity.Medium
        };
        vm.Messages.Add(firewallMessage);
        vm.Messages.Add(networkMessage);
        vm.ChatCategoryFilters.Add("All categories");
        vm.ChatCategoryFilters.Add("Firewall");
        vm.ChatCategoryFilters.Add("Network");

        vm.SelectedChatCategoryFilter = "Firewall";

        Assert.True(firewallMessage.IsVisible);
        Assert.False(networkMessage.IsVisible);

        vm.SelectedChatCategoryFilter = "All categories";

        Assert.True(firewallMessage.IsVisible);
        Assert.True(networkMessage.IsVisible);
    }

    [Fact]
    public async Task SendQueryCommand_AddsCapabilityReportOnce()
    {
        const string capabilityReport = "Data sources: ss available.";
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore())
        {
            UserQuery = "is my system secure?"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(1, vm.Messages.Count(message => message.Text == capabilityReport));
    }

    [Fact]
    public async Task FullAuditCommand_AddsCapabilityReportOnce()
    {
        const string capabilityReport = "Data sources: ss available.";
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore());

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(1, vm.Messages.Count(message => message.Text == capabilityReport));
    }

    [Fact]
    public async Task SendQueryCommand_TypedSshAudit_AppendsHistoryAndEnablesExport()
    {
        var agent = new TrackingAgent(AgentIntent.SshCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore())
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportAudit);
        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.SshCheck, vm.History[0].Intent);
    }

    [Fact]
    public async Task CheckDriftCommand_AfterShowBaseline_UsesLastAuditIntent()
    {
        var agent = new TrackingAgent(AgentIntent.SshCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore())
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.ShowBaselineCommand.Execute(null);
        await vm.ShowBaselineCommand.ExecutionTask;
        FlushDispatcher();

        vm.CheckDriftCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.SshCheck, agent.LastBaselineIntent);
        Assert.Equal(AgentIntent.SshCheck, agent.LastDriftIntent);
    }

    [Fact]
    public void SetBaselineCommand_IsDisabledBeforeAudit()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore());

        Assert.False(vm.SetBaselineCommand.CanExecute(null));
    }

    [Fact]
    public async Task SetAgent_ClearsStaleAuditState()
    {
        var vm = new AgentViewModel(new TrackingAgent(AgentIntent.SshCheck), new InMemoryAuditHistoryStore())
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        Assert.True(vm.CanExportAudit);
        Assert.True(vm.SetBaselineCommand.CanExecute(null));

        vm.SetAgent(new StubAgent());

        Assert.Null(vm.LastResult);
        Assert.False(vm.CanExportAudit);
        Assert.False(vm.SetBaselineCommand.CanExecute(null));
    }

    private static void FlushDispatcher() => Dispatcher.UIThread.RunJobs();

    private static Finding CreateFinding() => new()
    {
        Category = "Firewall",
        Severity = Severity.High,
        SourceHost = "localhost",
        Target = "22/tcp",
        TimeRangeStart = DateTime.UnixEpoch,
        TimeRangeEnd = DateTime.UnixEpoch,
        ShortDescription = "SSH exposed",
        Details = "detail",
        RuleId = "FW-001"
    };

    private sealed class StubAgent : IAgent
    {
        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = "stub"
            });

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "stub"
            });

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "stub",
                AgentFindings = new[] { finding }
            });

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "stub"
            });

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "stub"
            });

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "stub"
            });
    }

    private sealed class CapabilityReportAgent : IAgent
    {
        private readonly string _capabilityReport;

        public CapabilityReportAgent(string capabilityReport)
        {
            _capabilityReport = capabilityReport;
        }

        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.FullAudit));

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(CreateResult(intent));

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ExplainFinding));

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.SetBaseline));

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.CheckDrift));

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ShowBaseline));

        private AgentResult CreateResult(AgentIntent intent) => new()
        {
            Intent = intent,
            Summary = "stub",
            CapabilityReport = _capabilityReport
        };
    }

    private sealed class TrackingAgent : IAgent
    {
        private readonly AgentIntent _auditIntent;

        public TrackingAgent(AgentIntent auditIntent)
        {
            _auditIntent = auditIntent;
        }

        public AgentIntent? LastDriftIntent { get; private set; }
        public AgentIntent? LastBaselineIntent { get; private set; }

        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(CreateResult(_auditIntent));

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(CreateResult(intent));

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ExplainFinding));

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.SetBaseline));

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            LastDriftIntent = intent;
            return Task.FromResult(CreateResult(AgentIntent.CheckDrift));
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
        {
            LastBaselineIntent = intent;
            return Task.FromResult(CreateResult(AgentIntent.ShowBaseline));
        }

        private static AgentResult CreateResult(AgentIntent intent) => new()
        {
            Intent = intent,
            Summary = "stub",
            UtcTimestamp = DateTime.UtcNow
        };
    }
}
