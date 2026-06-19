using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
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

    private static SecurityAgent CreateAgent(IAuditHistoryStore historyStore, IAgentMemoryStore memoryStore, IBaselineStore? baselineStore = null)
    {
        var scanner = new TestScanner();
        var rule = new TestRule();
        return new SecurityAgent(
            new IScanner[] { scanner },
            new IRule[] { rule },
            new ExplanationProvider(),
            historyStore: historyStore,
            baselineStore: baselineStore,
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
        public string Id => "TEST-001";
        public string Category => "Test";
        public string Description => "Test rule for memory integration";
        public string WhatItChecks => "Always fails for testing";
        public IReadOnlyList<string> SupportedDataSources => new[] { "Test" };
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();
        public IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, "Test finding for memory integration", Severity.High, "target");
        }
    }
}
