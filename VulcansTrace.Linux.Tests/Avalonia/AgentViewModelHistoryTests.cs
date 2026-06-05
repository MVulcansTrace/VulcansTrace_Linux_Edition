using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentViewModelHistoryTests
{
    private static RemediationPlanBuilder PlanBuilder => new(new ExplanationProvider());
    [Fact]
    public async Task History_Accumulates_On_Audit()
    {
        var agent = new MockHistoryAgent();
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.Empty(vm.History);

        vm.LogText = "";
        await RunFullAuditAsync(vm);

        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.FullAudit, vm.History[0].Intent);
        Assert.Equal(2, vm.History[0].TotalFindings);
    }

    [Fact]
    public async Task History_Caps_At_Store_Max()
    {
        var agent = new MockHistoryAgent();
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

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
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

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
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

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
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        await RunFullAuditAsync(vm);

        Assert.False(vm.History[0].Exported);

        vm.MarkLatestAuditExported();

        Assert.True(vm.History[0].Exported);
    }

    [Fact]
    public void Constructor_Loads_Existing_History_From_Store()
    {
        var agent = new MockHistoryAgent();
        var store = new InMemoryAuditHistoryStore(maxEntries: 20);
        store.Append(CreateHistoryEntry("snap-1"));
        store.Append(CreateHistoryEntry("snap-2"));

        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.Equal(2, vm.History.Count);
        Assert.Equal("snap-2", vm.History[0].SnapshotId);
        Assert.Equal("snap-1", vm.History[1].SnapshotId);
    }

    [Fact]
    public void Constructor_Shows_HistoryPersistenceWarning()
    {
        var agent = new MockHistoryAgent();
        var store = new InMemoryAuditHistoryStore("Audit history persistence is unavailable.", maxEntries: 20);

        var vm = new AgentViewModel(agent, store, PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.Contains(vm.Messages, message => message.Text == "Audit history persistence is unavailable." && message.IsInfo);
    }

    private static AuditHistoryEntry CreateHistoryEntry(string snapshotId)
    {
        return new AuditHistoryEntry
        {
            SnapshotId = snapshotId,
            Intent = AgentIntent.FullAudit,
            TotalFindings = 1,
            SnapshotFindings = Array.Empty<AuditSnapshotFinding>()
        };
    }

    private static async Task RunFullAuditAsync(AgentViewModel vm)
    {
        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        Dispatcher.UIThread.RunJobs();
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

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Mock baseline set",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "Mock drift check",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "Mock baseline",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock remediation",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Mock verification",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock export",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock list",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "Mock resume",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock deleted",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Mock session note",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Mock step note",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }
    }
}
