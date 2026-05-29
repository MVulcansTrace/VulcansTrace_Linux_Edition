using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentViewModelHistoryTests
{
    [Fact]
    public async Task History_Accumulates_On_Audit()
    {
        var agent = new MockHistoryAgent();
        var vm = new AgentViewModel(agent);

        Assert.Empty(vm.History);

        vm.LogText = "";
        await RunFullAuditAsync(vm);

        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.FullAudit, vm.History[0].Intent);
        Assert.Equal(2, vm.History[0].TotalFindings);
    }

    [Fact]
    public async Task History_Caps_At_20()
    {
        var agent = new MockHistoryAgent();
        var vm = new AgentViewModel(agent);

        for (int i = 0; i < 25; i++)
        {
            await RunFullAuditAsync(vm);
        }

        Assert.Equal(20, vm.History.Count);
    }

    [Fact]
    public async Task History_Entry_Has_Correct_Counts()
    {
        var agent = new MockHistoryAgent();
        var vm = new AgentViewModel(agent);

        vm.LogText = "";
        await RunFullAuditAsync(vm);

        var entry = vm.History.FirstOrDefault();
        Assert.NotNull(entry);
        Assert.Equal(1, entry.CriticalCount);
        Assert.Equal(1, entry.HighCount);
        Assert.Equal(0, entry.MediumCount);
        Assert.Equal(2, entry.TotalFindings);
        Assert.True(entry.SnapshotFindings.Count > 0);
    }

    [Fact]
    public async Task CompareAuditsCommand_Requires_Two_HistoryEntries()
    {
        var agent = new MockHistoryAgent();
        var vm = new AgentViewModel(agent);

        Assert.False(vm.CanCompareAudits);
        Assert.False(vm.CompareAuditsCommand.CanExecute(null));

        await RunFullAuditAsync(vm);

        Assert.False(vm.CanCompareAudits);
        Assert.False(vm.CompareAuditsCommand.CanExecute(null));

        await RunFullAuditAsync(vm);

        Assert.True(vm.CanCompareAudits);
        Assert.True(vm.CompareAuditsCommand.CanExecute(null));
    }

    [Fact]
    public async Task MarkLatestAuditExported_Updates_MostRecentHistoryEntry()
    {
        var agent = new MockHistoryAgent();
        var vm = new AgentViewModel(agent);

        await RunFullAuditAsync(vm);

        Assert.False(vm.History[0].Exported);

        vm.MarkLatestAuditExported();

        Assert.True(vm.History[0].Exported);
    }

    private static async Task RunFullAuditAsync(AgentViewModel vm)
    {
        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
    }

    private sealed class MockHistoryAgent : IAgent
    {
        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            return RunAuditAsync(AgentIntent.FullAudit, rawLog, ct);
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "Mock audit",
                AgentFindings = new List<Finding>
                {
                    new Finding { RuleId = "FW-004", Severity = Severity.Critical, Target = "firewall", ShortDescription = "No firewall" },
                    new Finding { RuleId = "FW-002", Severity = Severity.High, Target = "SSH/22", ShortDescription = "SSH open" }
                },
                Warnings = new[] { "Mock warning" },
                UtcTimestamp = DateTime.UtcNow
            });
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "Mock explanation",
                AgentFindings = new List<Finding> { finding },
                Warnings = Array.Empty<string>()
            });
        }
    }
}
