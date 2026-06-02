using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentViewModelTests
{
    private static RemediationPlanBuilder PlanBuilder => new(new ExplanationProvider());

    [Fact]
    public void NotifySelectedFindingChanged_RefreshesExplainSelectedState()
    {
        var selected = CreateFinding();
        var hasSelection = false;
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
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
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder);
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
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore(), PlanBuilder)
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
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore(), PlanBuilder);

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(1, vm.Messages.Count(message => message.Text == capabilityReport));
    }

    [Fact]
    public async Task SendQueryCommand_TypedSshAudit_AppendsHistoryAndEnablesExport()
    {
        var agent = new TrackingAgent(AgentIntent.SshCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
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
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
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
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder);

        Assert.False(vm.SetBaselineCommand.CanExecute(null));
    }

    [Fact]
    public async Task SetAgent_ClearsStaleAuditState()
    {
        var vm = new AgentViewModel(new TrackingAgent(AgentIntent.SshCheck), new InMemoryAuditHistoryStore(), PlanBuilder)
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

    [Fact]
    public async Task SendQueryCommand_AgentError_AddsErrorMessageAndClearsBusyState()
    {
        var vm = new AgentViewModel(new ErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Agent error: boom" && message.IsInfo);
    }

    [Fact]
    public async Task CancelQueryCommand_CancelsActiveOperationAndClearsBusyState()
    {
        var vm = new AgentViewModel(new CancellableAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        Assert.True(vm.IsBusy);
        Assert.True(vm.CancelQueryCommand.CanExecute(null));

        vm.CancelQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Query cancelled." && message.IsInfo);
    }

    [Fact]
    public async Task SetBaselineCommand_AgentError_AddsErrorMessageAndClearsBusyState()
    {
        var vm = new AgentViewModel(new SetBaselineErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.SetBaselineCommand.Execute(null);
        await vm.SetBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Agent error: baseline boom" && message.IsInfo);
    }

    [Fact]
    public async Task CancelQueryCommand_CancelsActiveDriftOperationAndClearsBusyState()
    {
        var vm = new AgentViewModel(new CancellableDriftAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.CheckDriftCommand.Execute(null);
        Assert.True(vm.IsBusy);
        Assert.True(vm.CancelQueryCommand.CanExecute(null));

        vm.CancelQueryCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Query cancelled." && message.IsInfo);
    }

    [Fact]
    public async Task ShowBaselineCommand_SuppressesCapabilityPassedAndWarningSections()
    {
        var vm = new AgentViewModel(new NoisyBaselineAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        vm.Messages.Clear();

        vm.ShowBaselineCommand.Execute(null);
        await vm.ShowBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, message => message.Text == "baseline summary");
        Assert.DoesNotContain(vm.Messages, message => message.Text == "hidden capability report");
        Assert.DoesNotContain(vm.Messages, message => message.Text == "✓ 4 check(s) passed");
        Assert.DoesNotContain(vm.Messages, message => message.Text.StartsWith("Warnings:"));
    }

    [Fact]
    public async Task ExplainSelectedCommand_ExplainsFindingAndAddsMessages()
    {
        var finding = CreateFinding();
        var agent = new ExplainFindingAgent(finding);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            SelectedFindingProvider = () => finding
        };

        Assert.True(vm.ExplainSelectedCommand.CanExecute(null));

        vm.ExplainSelectedCommand.Execute(null);
        await vm.ExplainSelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Explain selected" && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "explanation summary");
        Assert.Contains(vm.Messages, m => m.Text.Contains("SSH exposed") && m.Severity == Severity.High);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task ExplainSelectedCommand_NoSelection_AddsGuidanceMessage()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            SelectedFindingProvider = () => null
        };

        vm.ExplainSelectedCommand.Execute(null);
        await vm.ExplainSelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "No finding is selected. Select a finding from the list first." && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task SetBaselineCommand_AfterAudit_DisplaysBaselineSummary()
    {
        var vm = new AgentViewModel(new SetBaselineSuccessAgent(), new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.SetBaselineCommand.CanExecute(null));
        vm.Messages.Clear();

        vm.SetBaselineCommand.Execute(null);
        await vm.SetBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Set baseline" && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "baseline saved" && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task CheckDriftCommand_AfterAudit_DisplaysDriftResult()
    {
        var agent = new DriftResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        vm.Messages.Clear();

        vm.CheckDriftCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text.StartsWith("Check drift") && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "drift summary");
        Assert.DoesNotContain(vm.Messages, m => m.Text == "hidden capability report");
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public async Task ExportSessionCommand_WithSessionResult_InvokesExportCallbackAndRefreshesTimeline()
    {
        var agent = new SessionResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "guided fix FW-001"
        };
        string? exported = null;
        vm.RequestExportSession = markdown =>
        {
            exported = markdown;
            return Task.FromResult(true);
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportSession);

        vm.ExportSessionCommand.Execute(null);
        await vm.ExportSessionCommand.ExecutionTask;
        FlushDispatcher();

        Assert.NotNull(exported);
        Assert.Contains("VulcansTrace Remediation Session Report", exported);
        Assert.Contains("abc12345", exported);
        Assert.Equal(1, agent.MarkExportedCallCount);
        Assert.Contains(vm.LastResult!.RemediationSession!.Timeline, e => e.Type == RemediationSessionEventType.Exported);
        Assert.Contains(vm.Messages, m => m.SessionId == "abc12345"
            && m.SessionTimeline.Any(e => e.Type == RemediationSessionEventType.Exported));
    }

    [Fact]
    public async Task ExportSessionCommand_WhenSaveIsCancelled_DoesNotMarkSessionExported()
    {
        var agent = new SessionResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder)
        {
            UserQuery = "guided fix FW-001"
        };
        vm.RequestExportSession = _ => Task.FromResult(false);

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.ExportSessionCommand.Execute(null);
        await vm.ExportSessionCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(0, agent.MarkExportedCallCount);
        Assert.DoesNotContain(vm.LastResult!.RemediationSession!.Timeline, e => e.Type == RemediationSessionEventType.Exported);
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

    private class StubAgent : IAgent
    {
        public virtual Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = "stub"
            });

        public virtual Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "stub"
            });

        public virtual Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "stub",
                AgentFindings = new[] { finding }
            });

        public virtual Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "stub"
            });

        public virtual Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "stub"
            });

        public virtual Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "stub"
            });

        public virtual Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "stub"
            });
    }

    private sealed class SessionResultAgent : StubAgent
    {
        private readonly Finding _finding = CreateFinding();
        private readonly RemediationSession _session;

        public SessionResultAgent()
        {
            _session = new RemediationSession
            {
                SessionId = "abc12345",
                SourceFindings = new[] { _finding },
                RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
                StepStates = new Dictionary<string, RemediationStepState>(),
                BlockedReasons = Array.Empty<string>(),
                Timeline = new[]
                {
                    new RemediationSessionEvent
                    {
                        TimestampUtc = DateTime.UtcNow,
                        Type = RemediationSessionEventType.Created,
                        Title = "Session started"
                    }
                }
            };
        }

        public int MarkExportedCallCount { get; private set; }

        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "session created",
                AgentFindings = new[] { _finding },
                RemediationSession = _session
            });
        }

        public override Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
        {
            MarkExportedCallCount++;
            var exportedSession = _session with
            {
                Timeline = _session.Timeline.Append(new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.Exported,
                    Title = $"Session {sessionId} exported"
                }).ToArray()
            };

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "session exported",
                AgentFindings = new[] { _finding },
                RemediationSession = exportedSession
            });
        }
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

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.VerifyRemediation));

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

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

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.VerifyRemediation));

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        private static AgentResult CreateResult(AgentIntent intent) => new()
        {
            Intent = intent,
            Summary = "stub",
            UtcTimestamp = DateTime.UtcNow
        };
    }

    private sealed class ErrorAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            throw new InvalidOperationException("boom");
        }
    }

    private sealed class CancellableAgent : StubAgent
    {
        public override async Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new AgentResult { Intent = AgentIntent.Help, Summary = "unreachable" };
        }
    }

    private sealed class SetBaselineErrorAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
        {
            throw new InvalidOperationException("baseline boom");
        }
    }

    private sealed class CancellableDriftAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override async Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new AgentResult { Intent = AgentIntent.CheckDrift, Summary = "unreachable" };
        }
    }

    private sealed class NoisyBaselineAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "baseline summary",
                CapabilityReport = "hidden capability report",
                PassedCount = 4,
                Warnings = new[] { "hidden warning" }
            });
    }

    private sealed class ExplainFindingAgent : StubAgent
    {
        private readonly Finding _finding;

        public ExplainFindingAgent(Finding finding)
        {
            _finding = finding;
        }

        public override Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "explanation summary",
                AgentFindings = new[] { _finding }
            });
    }

    private sealed class SetBaselineSuccessAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "baseline saved"
            });
    }

    private sealed class DriftResultAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "drift summary",
                CapabilityReport = "hidden capability report",
                PassedCount = 3
            });
    }
}
