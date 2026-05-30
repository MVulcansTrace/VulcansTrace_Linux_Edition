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
}
