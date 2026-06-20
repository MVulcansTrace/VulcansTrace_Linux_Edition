using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Memory;

public class SecurityAgentMemoryIntegrationTests
{
    [Fact]
    public async Task Restart_RestoresLastResultAndAnswersFollowUp()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var firstAgent = CreateAgent(historyStore, memoryStore);
        var auditResult = await firstAgent.AskAsync("run a full audit", null, CancellationToken.None);

        Assert.NotEmpty(auditResult.AgentFindings);
        Assert.NotNull(auditResult.SnapshotId);
        Assert.NotEmpty(auditResult.Suggestions);

        var secondAgent = CreateAgent(historyStore, memoryStore);
        var followUp = await secondAgent.AskAsync("what should I fix first?", null, CancellationToken.None);

        Assert.Equal(AgentIntent.PrioritizeRemediation, followUp.Intent);
        Assert.Contains("Fix in this order", followUp.Summary);
    }

    [Fact]
    public async Task Restart_RestoresFocusedFindingAndAnswersAnaphoricFix()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var firstAgent = CreateAgent(historyStore, memoryStore);
        await firstAgent.AskAsync("run a full audit", null, CancellationToken.None);
        await firstAgent.AskAsync("explain TEST-001", null, CancellationToken.None);

        var secondAgent = CreateAgent(historyStore, memoryStore);
        var followUp = await secondAgent.AskAsync("fix it", null, CancellationToken.None);

        Assert.Equal(AgentIntent.FixFinding, followUp.Intent);
        Assert.Contains("TEST-001", followUp.Summary);
    }

    [Fact]
    public async Task Restart_RestoresLastFindingsAndAnswersExplicitRuleId()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var firstAgent = CreateAgent(historyStore, memoryStore);
        await firstAgent.AskAsync("run a full audit", null, CancellationToken.None);

        var secondAgent = CreateAgent(historyStore, memoryStore);
        var followUp = await secondAgent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, followUp.Intent);
        Assert.Contains("TEST-001", followUp.Summary);
    }

    [Fact]
    public async Task RunAuditAsync_DirectCall_StampSuggestionsAndPersistsMemory()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var agent = CreateAgent(historyStore, memoryStore);
        var result = await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        Assert.NotEmpty(result.AgentFindings);
        Assert.NotEmpty(result.Suggestions);
        Assert.NotNull(memoryStore.Load());
        Assert.Equal(AgentIntent.FullAudit, memoryStore.Load()!.LastAuditIntent);
    }

    [Fact]
    public async Task SetBaselineAsync_DirectCall_StampsSuggestionsAndPersistsMemory()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        var baselineStore = new InMemoryBaselineStore();

        var agent = CreateAgent(historyStore, memoryStore, baselineStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var result = await agent.SetBaselineAsync("Known good", null, CancellationToken.None);

        Assert.Equal(AgentIntent.SetBaseline, result.Intent);
        Assert.Contains(result.Suggestions, s => s.Intent == AgentIntent.CheckDrift);
        Assert.NotNull(memoryStore.Load());
        Assert.Equal(AgentIntent.SetBaseline, memoryStore.Load()!.LastIntent);
    }

    [Fact]
    public async Task Constructor_NullRecentTurns_DoesNotThrow()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        await memoryStore.SaveAsync(new AgentMemorySnapshot { RecentTurns = null! });

        var exception = Record.Exception(() => CreateAgent(historyStore, memoryStore));

        Assert.Null(exception);
    }

    [Fact]
    public async Task Constructor_StaleSnapshot_IsIgnored()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        await memoryStore.SaveAsync(new AgentMemorySnapshot
        {
            UtcTimestamp = DateTime.UtcNow.AddDays(-31),
            LastAuditIntent = AgentIntent.FullAudit,
            LatestAuditSnapshotId = "old123"
        });

        var agent = CreateAgent(historyStore, memoryStore);
        var followUp = await agent.AskAsync("what should I fix first?", null, CancellationToken.None);

        // With no restored audit, prioritization should ask for a fresh audit.
        Assert.Contains("Run an audit first", followUp.Summary);
    }

    [Fact]
    public async Task Restart_RestoresWarningsAndLogAnalysisResult()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var logAnalysis = new AnalysisResult
        {
            TotalLines = 1,
            ParsedLines = 1,
            Findings = Array.Empty<Finding>(),
            Warnings = Array.Empty<string>(),
            ParseErrors = Array.Empty<string>(),
            Entries = Array.Empty<UnifiedEvent>()
        };
        var entry = new AuditHistoryEntry
        {
            SnapshotId = "snap01",
            Intent = AgentIntent.FullAudit,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding
                {
                    RuleId = "TEST-001",
                    Target = "test-target",
                    Severity = "High",
                    ShortDescription = "Test finding"
                }
            },
            Warnings = new[] { "Scanner not available" },
            LogAnalysisResult = logAnalysis
        };
        historyStore.Append(entry);

        var memoryStore = new InMemoryAgentMemoryStore();
        await memoryStore.SaveAsync(new AgentMemorySnapshot
        {
            LatestAuditSnapshotId = "snap01",
            LastAuditIntent = AgentIntent.FullAudit
        });

        var agent = CreateAgent(historyStore, memoryStore);

        Assert.NotNull(agent.LastResult);
        Assert.Equal(entry.Warnings, agent.LastResult!.Warnings);
        Assert.Equal(logAnalysis.TotalLines, agent.LastResult.LogAnalysisResult!.TotalLines);
    }

    [Fact]
    public async Task Constructor_CorruptSnapshotFields_DoesNotThrow()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var entry = new AuditHistoryEntry
        {
            SnapshotId = "snap01",
            Intent = AgentIntent.FullAudit,
            SnapshotFindings = new[]
            {
                new AuditSnapshotFinding
                {
                    RuleId = "TEST-001",
                    Target = "",
                    Severity = "High",
                    ShortDescription = "",
                    Category = "",
                    Fingerprint = null
                }
            }
        };
        historyStore.Append(entry);

        var memoryStore = new InMemoryAgentMemoryStore();
        await memoryStore.SaveAsync(new AgentMemorySnapshot
        {
            LatestAuditSnapshotId = "snap01",
            LastAuditIntent = AgentIntent.FullAudit
        });

        var exception = Record.Exception(() => CreateAgent(historyStore, memoryStore));
        Assert.Null(exception);

        var agent = CreateAgent(historyStore, memoryStore);
        var followUp = await agent.AskAsync("explain TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, followUp.Intent);
        Assert.Contains("TEST-001", followUp.Summary);
        Assert.NotEmpty(followUp.AgentFindings);
        Assert.NotNull(followUp.AgentFindings[0].Fingerprint);
    }

    [Fact]
    public async Task Restart_RestoresRuleHistory_AndTracksTrend()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var firstAgent = CreateAgent(historyStore, memoryStore);
        await firstAgent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var secondAgent = CreateAgent(historyStore, memoryStore);
        var loadedMemory = memoryStore.Load();

        Assert.NotNull(loadedMemory);
        Assert.Single(loadedMemory.RuleHistory);
        Assert.True(loadedMemory.RuleHistory.ContainsKey("TEST-001"));
        var entry = loadedMemory.RuleHistory["TEST-001"];
        Assert.Equal(RuleStatusTrend.New, entry.Trend);
        Assert.Single(entry.SeverityHistory);

        // Re-run with a rule that now reports Critical severity.
        var worseningAgent = CreateAgent(historyStore, memoryStore, rule: new TestRule(Severity.Critical));
        await worseningAgent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        entry = loadedMemory.RuleHistory["TEST-001"];
        Assert.Equal(RuleStatusTrend.Worsening, entry.Trend);
        Assert.Equal(2, entry.SeverityHistory.Count);
        Assert.Equal(Severity.Critical, entry.LastSeverity);
    }

    [Fact]
    public async Task VerifyFindingAsync_ReRunsAudit_AndReportsStatus()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var agent = CreateAgent(historyStore, memoryStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var verifyResult = await agent.VerifyFindingAsync("TEST-001", CancellationToken.None);

        Assert.Equal(AgentIntent.VerifyRemediation, verifyResult.Intent);
        Assert.Contains("TEST-001", verifyResult.Summary);
    }

    [Fact]
    public async Task VerifyFindingAsync_WhenRuleNoLongerFails_RecordsVerifiedFixed()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var failingAgent = CreateAgent(historyStore, memoryStore, rule: new TestRule(Severity.High));
        await failingAgent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        // Swap to a passing rule, restore state, and verify the original rule.
        var passingAgent = CreateAgent(historyStore, memoryStore, rule: new PassingTestRule());
        var verifyResult = await passingAgent.VerifyFindingAsync("TEST-001", CancellationToken.None);

        Assert.Contains("no longer detected", verifyResult.Summary, StringComparison.OrdinalIgnoreCase);

        var loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        Assert.True(loadedMemory.RuleHistory.ContainsKey("TEST-001"));
        Assert.NotNull(loadedMemory.RuleHistory["TEST-001"].LastVerifiedFixedUtc);
    }

    [Fact]
    public async Task AskAsync_VerifyFindingQuery_RoutesToTargetedVerification()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var failingAgent = CreateAgent(historyStore, memoryStore, rule: new TestRule(Severity.High));
        await failingAgent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var passingAgent = CreateAgent(historyStore, memoryStore, rule: new PassingTestRule());
        var verifyResult = await passingAgent.AskAsync("verify finding TEST-001", null, CancellationToken.None);

        Assert.Equal(AgentIntent.VerifyRemediation, verifyResult.Intent);
        Assert.Contains("no longer detected", verifyResult.Summary, StringComparison.OrdinalIgnoreCase);

        var loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        Assert.NotNull(loadedMemory.RuleHistory["TEST-001"].LastVerifiedFixedUtc);
    }

    [Fact]
    public async Task VerifyFindingAsync_WithoutPriorAudit_AsksForAudit()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var agent = CreateAgent(historyStore, memoryStore);
        var verifyResult = await agent.VerifyFindingAsync("TEST-001", CancellationToken.None);

        Assert.Contains("Run an audit first", verifyResult.Summary);
    }

    [Fact]
    public async Task StartRemediationAsync_DoesNotRecordRemediationAttempt()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        var sessionStore = new InMemorySessionStore();

        var agent = CreateAgent(historyStore, memoryStore, sessionStore: sessionStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);

        var result = await agent.StartRemediationAsync("TEST-001", CancellationToken.None);

        Assert.NotNull(result.RemediationSession);
        var loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        Assert.Null(loadedMemory.RuleHistory["TEST-001"].LastRemediationAttemptUtc);
    }

    [Theory]
    [InlineData(RemediationStepState.InProgress)]
    [InlineData(RemediationStepState.Completed)]
    [InlineData(RemediationStepState.Failed)]
    public async Task UpdateRemediationStepStateAsync_ProgressState_RecordsRemediationAttempt(RemediationStepState state)
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        var sessionStore = new InMemorySessionStore();

        var agent = CreateAgent(historyStore, memoryStore, sessionStore: sessionStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);
        var sessionResult = await agent.StartRemediationAsync("TEST-001", CancellationToken.None);
        var sessionId = sessionResult.RemediationSession!.SessionId;

        await agent.UpdateRemediationStepStateAsync(sessionId, "TEST-001", state, CancellationToken.None);

        var loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        Assert.NotNull(loadedMemory.RuleHistory["TEST-001"].LastRemediationAttemptUtc);
    }

    [Theory]
    [InlineData(RemediationStepState.Pending)]
    [InlineData(RemediationStepState.Skipped)]
    public async Task UpdateRemediationStepStateAsync_NonAttemptState_DoesNotRecordRemediationAttempt(RemediationStepState state)
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        var sessionStore = new InMemorySessionStore();

        var agent = CreateAgent(historyStore, memoryStore, sessionStore: sessionStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);
        var sessionResult = await agent.StartRemediationAsync("TEST-001", CancellationToken.None);
        var sessionId = sessionResult.RemediationSession!.SessionId;

        await agent.UpdateRemediationStepStateAsync(sessionId, "TEST-001", state, CancellationToken.None);

        var loadedMemory = memoryStore.Load();
        Assert.NotNull(loadedMemory);
        Assert.Null(loadedMemory.RuleHistory["TEST-001"].LastRemediationAttemptUtc);
    }

    [Fact]
    public async Task Restart_PersistsCheckedCategories_AcrossTargetedAudits()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var firstAgent = CreateAgent(historyStore, memoryStore);
        await firstAgent.AskAsync("check firewall", null, CancellationToken.None);

        var afterFirst = memoryStore.Load();
        Assert.NotNull(afterFirst);
        Assert.Contains(afterFirst.CheckedCategories, c => c.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase));

        // Rehydrate into a fresh agent and run a second targeted audit; coverage must accumulate.
        var secondAgent = CreateAgent(historyStore, memoryStore);
        await secondAgent.AskAsync("check ssh", null, CancellationToken.None);

        var afterSecond = memoryStore.Load();
        Assert.NotNull(afterSecond);
        Assert.Contains(afterSecond.CheckedCategories, c => c.Category.Equals("Firewall", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(afterSecond.CheckedCategories, c => c.Category.Equals("SSH", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task FilterCategoryFallback_PersistsCoverageForFallbackAudit()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();

        var agent = CreateAgent(historyStore, memoryStore);

        // No prior audit → FilterCategory runs a fallback NetworkCheck audit. The recorded category
        // must survive the SnapshotState/RestoreState wrapper (regression test for coverage loss).
        await agent.AskAsync("show only network issues", null, CancellationToken.None);

        var loaded = memoryStore.Load();
        Assert.NotNull(loaded);
        Assert.Contains(loaded.CheckedCategories, c => c.Category.Equals("Network", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CheckDrift_PreservesCumulativeMemoryFromReAudit()
    {
        var historyStore = new InMemoryAuditHistoryStore();
        var memoryStore = new InMemoryAgentMemoryStore();
        var baselineStore = new InMemoryBaselineStore();

        var agent = CreateAgent(historyStore, memoryStore, baselineStore);
        await agent.RunAuditAsync(AgentIntent.FullAudit, null, CancellationToken.None);
        await agent.SetBaselineAsync("baseline", null, CancellationToken.None);

        // Drift detection runs the same FullAudit intent inside a SnapshotState/RestoreState wrapper.
        // Cumulative memory (rule history + coverage) from that re-audit must survive the restore.
        await agent.AskAsync("check drift", null, CancellationToken.None);

        var loaded = memoryStore.Load();
        Assert.NotNull(loaded);
        Assert.True(loaded.RuleHistory.ContainsKey("TEST-001"));
        Assert.Equal(2, loaded.RuleHistory["TEST-001"].SeverityHistory.Count);
        Assert.Equal(IntentCategoryMap.AllCategories.Count, loaded.CheckedCategories.Count);
    }

    private static SecurityAgent CreateAgent(
        IAuditHistoryStore historyStore,
        IAgentMemoryStore memoryStore,
        IBaselineStore? baselineStore = null,
        IRule? rule = null,
        ISessionStore? sessionStore = null)
    {
        var scanner = new TestScanner();
        rule ??= new TestRule();
        return new SecurityAgent(
            new IScanner[] { scanner },
            new IRule[] { rule },
            new ExplanationProvider(),
            historyStore: historyStore,
            baselineStore: baselineStore,
            sessionStore: sessionStore,
            memoryStore: memoryStore);
    }

    private sealed class TestScanner : IScanner
    {
        public string Name => "Test";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class TestRule : IRule
    {
        private readonly Severity _severity;

        public TestRule(Severity severity = Severity.High)
        {
            _severity = severity;
        }

        public string Id => "TEST-001";
        public string Category => "Test";
        public string Description => "Test rule for memory integration";
        public string WhatItChecks => "Always fails for testing";
        public IReadOnlyList<string> SupportedDataSources => new[] { "Test" };
        public Severity Severity => _severity;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, "Test finding for memory integration", _severity, "target");
        }
    }

    private sealed class PassingTestRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Test";
        public string Description => "Test rule that passes";
        public string WhatItChecks => "Always passes for testing";
        public IReadOnlyList<string> SupportedDataSources => new[] { "Test" };
        public Severity Severity => Severity.Info;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Pass(Id, Category, Id, "Test rule passes");
        }
    }
}
