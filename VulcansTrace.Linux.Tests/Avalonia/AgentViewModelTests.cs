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
        var vm = new AgentViewModel(new StubAgent())
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
    }
}
