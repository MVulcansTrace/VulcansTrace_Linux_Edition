using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SecurityAgentTests
{
    [Fact]
    public async Task AskAsync_HelpQuery_ReturnsHelpResult()
    {
        var agent = CreateAgent();

        var result = await agent.AskAsync("what can you do?", null, CancellationToken.None);

        Assert.Equal(AgentIntent.Help, result.Intent);
        Assert.Contains("help you audit", result.Summary);
    }

    [Fact]
    public async Task AskAsync_FullAudit_RunsRulesAndReturnsFindings()
    {
        var agent = CreateAgent();

        var result = await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FullAudit, result.Intent);
        Assert.NotNull(result.AgentFindings);
        Assert.NotNull(result.Warnings);
        Assert.NotEmpty(result.Summary);
    }

    [Fact]
    public async Task RunAuditAsync_FirewallCheck_OnlyFirewallRulesRun()
    {
        var agent = CreateAgent();

        var result = await agent.RunAuditAsync(AgentIntent.FirewallCheck, null, CancellationToken.None);

        Assert.Equal(AgentIntent.FirewallCheck, result.Intent);
        // Even with no real firewall, rules evaluate and may return findings
        Assert.NotNull(result.AgentFindings);
    }

    [Fact]
    public async Task RunAuditAsync_Cancellation_ThrowsOperationCanceledException()
    {
        var agent = CreateAgent();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await agent.RunAuditAsync(AgentIntent.FullAudit, null, cts.Token));
    }

    [Fact]
    public async Task ExplainFindingAsync_ReturnsSingleFindingWithRichSummary()
    {
        var agent = CreateAgent();
        var finding = new Finding
        {
            Category = "Test",
            Severity = Severity.Low,
            SourceHost = "localhost",
            Target = "test-target",
            ShortDescription = "Test finding",
            Details = "This is a detailed explanation.",
            TimeRangeStart = DateTime.UtcNow,
            TimeRangeEnd = DateTime.UtcNow
        };

        var result = await agent.ExplainFindingAsync(finding, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Contains("Test finding", result.Summary);
        Assert.Contains("What was found", result.Summary);
        Assert.Contains("Why it matters", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_WithoutReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("explain this finding", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("specify a finding", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_WithUnknownReference_ReturnsGuidance()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("explain UNKNOWN-999", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("don't have a finding matching", result.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_AfterAudit_ResolvesByReference()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // First run an audit to populate _lastFindings
        var auditResult = await agent.AskAsync("is my system secure?", null, CancellationToken.None);
        Assert.Single(auditResult.AgentFindings);

        // Then ask to explain the finding by its rule ID
        var explainResult = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, explainResult.Intent);
        Assert.Single(explainResult.AgentFindings);
        Assert.Contains("Test finding should be explained", explainResult.Summary);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_AfterAudit_ResolvesByCategory()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // First run an audit
        await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        // Then ask to explain by category keyword
        var explainResult = await agent.AskAsync("explain the firewall finding", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, explainResult.Intent);
        Assert.Single(explainResult.AgentFindings);
    }

    [Fact]
    public async Task AskAsync_ExplainFinding_ByRuleId_RunsSingleRule()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        // Ask to explain a specific rule ID without prior audit
        var result = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("Test finding should be explained", result.AgentFindings[0].ShortDescription);
    }

    [Fact]
    public async Task RunAuditAsync_FindingIncludesRuleId()
    {
        var agent = new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider());

        var result = await agent.AskAsync("is my system secure?", null, CancellationToken.None);

        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-001", result.AgentFindings[0].RuleId);
    }

    private static SecurityAgent CreateAgent()
    {
        var scanners = new IScanner[]
        {
            new FirewallScanner(),
            new PortScanner(),
            new ServiceScanner(),
            new NetworkScanner()
        };

        var rules = new IRule[]
        {
            new FirewallActiveRule(),
            new FirewallDefaultDropRule(),
            new TelnetServiceRule(),
            new SshServiceRule(),
            new DefaultRouteRule()
        };

        var explanationProvider = new ExplanationProvider();
        return new SecurityAgent(scanners, rules, explanationProvider);
    }

    private sealed class NoopScanner : IScanner
    {
        public string Name => "Noop";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class AlwaysFailRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Firewall";
        public string Description => "Test finding should be explained";

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(
                Id,
                Category,
                Id,
                Description,
                Severity.Low,
                "test-target");
        }
    }
}
