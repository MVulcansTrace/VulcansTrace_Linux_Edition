using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

/// <summary>
/// Integration tests that drive <see cref="SecurityAgent.AskAsync"/> across multiple
/// turns to verify the dialogue context wiring in production, without manually
/// seeding <see cref="DialogueContext.Entities.LastTopic"/>.
/// </summary>
public class SecurityAgentDialogueIntegrationTests
{
    [Fact]
    public async Task AskAsync_ExplainThenFixIt_ResolvesFocusedFinding()
    {
        var agent = CreateAgent();

        var audit = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Single(audit.AgentFindings);
        Assert.Equal("TEST-001", audit.AgentFindings[0].RuleId);

        var explain = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, explain.Intent);
        Assert.Single(explain.AgentFindings);

        var fix = await agent.AskAsync("fix it", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FixFinding, fix.Intent);
        Assert.NotNull(fix.RemediationPlan);
        Assert.Single(fix.AgentFindings);
        Assert.Equal("TEST-001", fix.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_ExplainThenFixItAgain_ResolvesFocusedFinding()
    {
        var agent = CreateAgent();

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        var fix = await agent.AskAsync("fix it again", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FixFinding, fix.Intent);
        Assert.Single(fix.AgentFindings);
        Assert.Equal("TEST-001", fix.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_ExplainItAfterExplain_ResolvesFocusedFinding()
    {
        var agent = CreateAgent();

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var firstExplain = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, firstExplain.Intent);

        var secondExplain = await agent.AskAsync("explain it", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, secondExplain.Intent);
        Assert.Single(secondExplain.AgentFindings);
        Assert.Equal("TEST-001", secondExplain.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_RemediateThenVerifyIt_ResolvesActiveSession()
    {
        var agent = CreateAgent();

        await agent.AskAsync("audit everything", null, CancellationToken.None);
        var explain = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, explain.Intent);

        var remediate = await agent.AskAsync("remediate it", null, CancellationToken.None);
        Assert.Equal(AgentIntent.StartRemediation, remediate.Intent);
        Assert.NotNull(remediate.RemediationSession);
        var sessionId = remediate.RemediationSession!.SessionId;

        var verify = await agent.AskAsync("verify it", null, CancellationToken.None);
        Assert.Equal(AgentIntent.VerifyRemediation, verify.Intent);
        Assert.NotNull(verify.RemediationSession);
        Assert.Equal(sessionId, verify.RemediationSession!.SessionId);
        Assert.NotNull(verify.RemediationSession.VerificationResult);
    }

    [Fact]
    public async Task AskAsync_AuditThenFilterCategory_ResolvesCategory()
    {
        var agent = CreateAgent();

        var audit = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Single(audit.AgentFindings);

        var filter = await agent.AskAsync("only the Firewall ones", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FilterCategory, filter.Intent);
        Assert.Single(filter.AgentFindings);
        Assert.Equal("TEST-001", filter.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_ExplainOrdinalThenFixIt_ResolvesOrdinalFinding()
    {
        var agent = CreateMultiFindingAgent();

        var audit = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Equal(2, audit.AgentFindings.Count);

        // RankFindings orders by severity descending, then category ascending.
        // Both findings are High, and Firewall sorts before SSH, so the second is SSH.
        var explain = await agent.AskAsync("explain the second one", null, CancellationToken.None);
        Assert.Equal(AgentIntent.ExplainFinding, explain.Intent);
        Assert.Single(explain.AgentFindings);
        Assert.Equal("TEST-SSH-001", explain.AgentFindings[0].RuleId);

        var fix = await agent.AskAsync("fix it", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FixFinding, fix.Intent);
        Assert.Single(fix.AgentFindings);
        Assert.Equal("TEST-SSH-001", fix.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_MultiFindingCategoryFilter_ResolvesCategory()
    {
        var agent = CreateMultiFindingAgent();

        var audit = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Equal(2, audit.AgentFindings.Count);

        var filter = await agent.AskAsync("only the SSH ones", null, CancellationToken.None);
        Assert.Equal(AgentIntent.FilterCategory, filter.Intent);
        Assert.Single(filter.AgentFindings);
        Assert.Equal("TEST-SSH-001", filter.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_SshService_UsesSpecificSshIntent()
    {
        var agent = CreateMultiFindingAgent();

        var result = await agent.AskAsync("check my ssh service", null, CancellationToken.None);

        Assert.Equal(AgentIntent.SshCheck, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-SSH-001", result.AgentFindings[0].RuleId);
    }

    [Fact]
    public async Task AskAsync_RecurringFinding_DiagnosticDialogueFlow()
    {
        var agent = CreateAgentWithRecurringMemory("TEST-001");

        var audit = await agent.AskAsync("audit everything", null, CancellationToken.None);
        Assert.Single(audit.AgentFindings);
        Assert.Equal("TEST-001", audit.AgentFindings[0].RuleId);

        var investigate = await agent.AskAsync("TEST-001 came back again", null, CancellationToken.None);
        Assert.Equal(AgentIntent.InvestigateRecurrence, investigate.Intent);
        Assert.NotNull(investigate.Narrative);
        Assert.Contains("config-management", investigate.Narrative!.KeyFindingsParagraph);

        var answer = await agent.AskAsync("I'm using Ansible", null, CancellationToken.None);
        Assert.Equal(AgentIntent.AnswerDiagnosticQuestion, answer.Intent);
        Assert.Contains("config-management tool", answer.Narrative!.KeyFindingsParagraph);
    }

    private static SecurityAgent CreateAgent()
    {
        return new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            sessionStore: new InMemorySessionStore());
    }

    private static SecurityAgent CreateAgentWithRecurringMemory(string ruleId)
    {
        var now = DateTime.UtcNow;
        var history = new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                Trend = RuleStatusTrend.Stable,
                FirstSeenUtc = now.AddDays(-14),
                LastSeenUtc = now.AddDays(-1),
                SeverityHistory = new[]
                {
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-14), Severity = Severity.High, Target = "target" },
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-7), Severity = Severity.High, Target = "target" },
                    new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-1), Severity = Severity.High, Target = "target" }
                },
                RemediationCycles = new[]
                {
                    new RemediationCycle
                    {
                        CycleNumber = 1,
                        AttemptedUtc = now.AddDays(-10),
                        VerifiedFixedUtc = now.AddDays(-9),
                        ReturnedUtc = now.AddDays(-8)
                    },
                    new RemediationCycle
                    {
                        CycleNumber = 2,
                        AttemptedUtc = now.AddDays(-5),
                        VerifiedFixedUtc = now.AddDays(-4),
                        ReturnedUtc = now.AddDays(-2)
                    }
                }
            }
        };

        var memoryStore = new InMemoryAgentMemoryStore();
        memoryStore.SaveAsync(new AgentMemorySnapshot
        {
            UtcTimestamp = now,
            RuleHistory = history
        }).Wait();

        return new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule() },
            new ExplanationProvider(),
            sessionStore: new InMemorySessionStore(),
            memoryStore: memoryStore);
    }

    private static SecurityAgent CreateMultiFindingAgent()
    {
        return new SecurityAgent(
            new IScanner[] { new NoopScanner() },
            new IRule[] { new AlwaysFailRule(), new AlwaysFailSshRule() },
            new ExplanationProvider(),
            sessionStore: new InMemorySessionStore());
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
        public string WhatItChecks => "Test rule that always fails";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.High;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 4.5",
                ControlName = "Implement and Manage a Firewall on Servers",
                WhyItMatters = "Test why it matters.",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 3.5.1.3 — Ensure default deny firewall policy"
            }
        };

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(
                Id,
                Category,
                Id,
                Description,
                Severity.High,
                "test-target",
                cisMappings: CisMappings);
        }
    }

    private sealed class AlwaysFailSshRule : IRule
    {
        public string Id => "TEST-SSH-001";
        public string Category => "SSH";
        public string Description => "Test SSH finding should be explained";
        public string WhatItChecks => "Test SSH rule that always fails";
        public IReadOnlyList<string> SupportedDataSources => new[] { "test" };
        public Severity Severity => Severity.High;

        public IReadOnlyList<CisBenchmarkMapping> CisMappings => new[]
        {
            new CisBenchmarkMapping
            {
                ControlId = "CIS 5.1",
                ControlName = "Configure SSH Server",
                WhyItMatters = "Test why SSH matters.",
                BenchmarkReference = "CIS Ubuntu 24.04 LTS 5.2.1 — Ensure permissions on /etc/ssh/sshd_config"
            }
        };

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(
                Id,
                Category,
                Id,
                Description,
                Severity.High,
                "ssh-target",
                cisMappings: CisMappings);
        }
    }
}
