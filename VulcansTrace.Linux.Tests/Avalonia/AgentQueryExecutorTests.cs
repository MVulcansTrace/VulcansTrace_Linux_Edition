using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentQueryExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_ExplainFindingWithoutReferenceAndSelectedFinding_CallsExplainFinding()
    {
        var agent = new TrackingAgent();
        var executor = new AgentQueryExecutor(() => agent);
        var selected = CreateFinding();
        using var cts = new CancellationTokenSource();

        var result = await executor.ExecuteAsync(
            "explain this finding",
            rawLog: "raw log",
            selectedFindingProvider: () => selected,
            cts.Token);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Equal(1, agent.ExplainFindingCalls);
        Assert.Equal(0, agent.AskCalls);
        Assert.Same(selected, agent.ExplainedFinding);
        Assert.Equal(cts.Token, agent.ObservedToken);
    }

    [Fact]
    public async Task ExecuteAsync_ExplainFindingWithoutSelectedFinding_FallsBackToAsk()
    {
        var agent = new TrackingAgent();
        var executor = new AgentQueryExecutor(() => agent);

        var result = await executor.ExecuteAsync(
            "explain this finding",
            rawLog: "raw log",
            selectedFindingProvider: () => null,
            CancellationToken.None);

        Assert.Equal(AgentIntent.FullAudit, result.Intent);
        Assert.Equal(0, agent.ExplainFindingCalls);
        Assert.Equal(1, agent.AskCalls);
        Assert.Equal("explain this finding", agent.ObservedQuery);
        Assert.Equal("raw log", agent.ObservedRawLog);
    }

    [Fact]
    public async Task ExecuteAsync_ExplainFindingWithExplicitReference_FallsBackToAsk()
    {
        var agent = new TrackingAgent();
        var executor = new AgentQueryExecutor(() => agent);
        var selected = CreateFinding();

        await executor.ExecuteAsync(
            "explain FW-001",
            rawLog: null,
            selectedFindingProvider: () => selected,
            CancellationToken.None);

        Assert.Equal(0, agent.ExplainFindingCalls);
        Assert.Equal(1, agent.AskCalls);
        Assert.Equal("explain FW-001", agent.ObservedQuery);
    }

    [Fact]
    public async Task ExecuteAsync_NormalQuery_CallsAskWithRawLogAndCancellationToken()
    {
        var agent = new TrackingAgent();
        var executor = new AgentQueryExecutor(() => agent);
        using var cts = new CancellationTokenSource();

        await executor.ExecuteAsync(
            "check firewall",
            rawLog: "firewall log",
            selectedFindingProvider: null,
            cts.Token);

        Assert.Equal(1, agent.AskCalls);
        Assert.Equal(0, agent.ExplainFindingCalls);
        Assert.Equal("check firewall", agent.ObservedQuery);
        Assert.Equal("firewall log", agent.ObservedRawLog);
        Assert.Equal(cts.Token, agent.ObservedToken);
    }

    [Fact]
    public async Task ExecuteAsync_UsesLatestAgentFromFactory()
    {
        var firstAgent = new TrackingAgent();
        var secondAgent = new TrackingAgent();
        var current = firstAgent;
        var executor = new AgentQueryExecutor(() => current);

        await executor.ExecuteAsync("check firewall", null, null, CancellationToken.None);
        current = secondAgent;
        await executor.ExecuteAsync("check ssh", null, null, CancellationToken.None);

        Assert.Equal(1, firstAgent.AskCalls);
        Assert.Equal("check firewall", firstAgent.ObservedQuery);
        Assert.Equal(1, secondAgent.AskCalls);
        Assert.Equal("check ssh", secondAgent.ObservedQuery);
    }

    private static Finding CreateFinding() => new()
    {
        RuleId = "FW-001",
        Category = "Firewall",
        Severity = Severity.High,
        SourceHost = "localhost",
        Target = "22/tcp",
        ShortDescription = "SSH exposed",
        Details = "Details",
        TimeRangeStart = DateTime.UtcNow,
        TimeRangeEnd = DateTime.UtcNow
    };

    private sealed class TrackingAgent : IAgent
    {
        public int AskCalls { get; private set; }
        public int ExplainFindingCalls { get; private set; }
        public string? ObservedQuery { get; private set; }
        public string? ObservedRawLog { get; private set; }
        public CancellationToken ObservedToken { get; private set; }
        public Finding? ExplainedFinding { get; private set; }

        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            AskCalls++;
            ObservedQuery = query;
            ObservedRawLog = rawLog;
            ObservedToken = ct;

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FullAudit,
                Summary = "asked"
            });
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = intent, Summary = "audit" });

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
        {
            ExplainFindingCalls++;
            ExplainedFinding = finding;
            ObservedToken = ct;

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "explained",
                AgentFindings = new[] { finding }
            });
        }

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.SetBaseline, Summary = "baseline" });

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.CheckDrift, Summary = "drift" });

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ShowBaseline, Summary = "show baseline" });

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "remediation" });

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.VerifyRemediation, Summary = "verify" });

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "exported" });
    }
}
