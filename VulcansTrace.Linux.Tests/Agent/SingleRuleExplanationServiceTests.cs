using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SingleRuleExplanationServiceTests
{
    [Fact]
    public async Task ExplainAsync_FailingRule_ReturnsFindingWithoutUpdatingState()
    {
        var state = new AgentAuditState();
        var service = CreateService(new FailingRule(), state: state);

        var result = await service.ExplainAsync(new FailingRule(), EmptyHistory(), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("Explanation for [High] Test failed\n\nexplanation:TEST-001", result.Summary);
        Assert.Equal(1, result.FailedCount);
        Assert.Null(state.LastResult);
        Assert.Null(state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public async Task ExplainAsync_DisabledRule_ReturnsPolicyMessageAndKeepsLastResult()
    {
        var state = new AgentAuditState();
        var previous = new AgentResult { Intent = AgentIntent.FullAudit, Summary = "previous" };
        var previousFinding = CreateFinding("TEST-001", "previous-target");
        state.RememberAudit(previous, AgentIntent.FullAudit, new[] { ("TEST-001", previousFinding) });
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Workstation, new RulePolicy { Enabled = false });
        var rule = new FailingRule();
        var service = CreateService(rule, state: state, policyProvider: policyStore, machineRole: MachineRole.Workstation);

        var result = await service.ExplainAsync(rule, EmptyHistory(), CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Contains("Rule TEST-001 is disabled by policy for Workstation.", result.Summary);
        Assert.Equal(1, result.PassedCount);
        Assert.Same(previous, state.LastResult);
        Assert.Same(previousFinding, state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public async Task ExplainAsync_SuppressedFailure_StillReturnsFinding()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var rule = new FailingRule();
        var service = CreateService(rule, suppressionStore: suppressionStore);

        var result = await service.ExplainAsync(rule, EmptyHistory(), CancellationToken.None);

        Assert.Single(result.AgentFindings);
        Assert.Equal(RuleStatus.Failed, result.RuleResults[0].Status);
        Assert.Equal(0, result.SuppressedCount);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("suppressed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExplainAsync_PassingRule_ReturnsPassedSummary()
    {
        var rule = new PassingRule();
        var service = CreateService(rule);

        var result = await service.ExplainAsync(rule, EmptyHistory(), CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Equal("Rule TEST-002 passed — no issue to explain.", result.Summary);
        Assert.Equal(1, result.PassedCount);
    }

    [Fact]
    public async Task ExplainAsync_StandardDepth_NoAdaptiveSections()
    {
        var rule = new FailingRule();
        var service = CreateService(rule);

        var result = await service.ExplainAsync(rule, EmptyHistory(), CancellationToken.None);

        Assert.DoesNotContain("History", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainAsync_FamiliarDepth_AddsHistorySection()
    {
        var rule = new FailingRule();
        var service = CreateService(rule);
        var history = CreateHistory("TEST-001", Severity.High, Severity.High);

        var result = await service.ExplainAsync(rule, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("[TEST-001]", result.Summary);
        Assert.Contains("2 retained audit snapshot(s)", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainAsync_RecurringDepth_AddsRootCauseSection()
    {
        var rule = new FwRule();
        var service = CreateService(rule);
        var history = CreateHistoryWithCycles("FW-001", Severity.High, closedCycleCount: 2);

        var result = await service.ExplainAsync(rule, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("Root cause", result.Summary);
        Assert.Contains("firewall keeps reverting", result.Summary);
        Assert.Contains("completed 2 remediation cycle(s)", result.Summary);
        Assert.DoesNotContain("What changed", result.Summary);
    }

    [Fact]
    public async Task ExplainAsync_EscalatingDepth_AddsSeverityTimeline()
    {
        var rule = new FailingRule();
        var service = CreateService(rule);
        var history = CreateHistory("TEST-001", Severity.Medium, Severity.High);

        var result = await service.ExplainAsync(rule, history, CancellationToken.None);

        Assert.Contains("History", result.Summary);
        Assert.Contains("What changed", result.Summary);
        Assert.Contains("**[TEST-001]** severity escalated from Medium to High", result.Summary);
        Assert.DoesNotContain("Root cause", result.Summary);
        Assert.DoesNotContain("completed 0 remediation cycle(s)", result.Summary);
    }

    private static SingleRuleExplanationService CreateService(
        IRule rule,
        AgentAuditState? state = null,
        IRulePolicyProvider? policyProvider = null,
        ISuppressionStore? suppressionStore = null,
        MachineRole machineRole = MachineRole.Server)
    {
        state ??= new AgentAuditState();
        var scannerCoordinator = new ScannerCoordinator(new[] { new NoopScanner() });
        var ruleEvaluationService = new RuleEvaluationService(new[] { rule }, machineRole, policyProvider);
        var findingAssemblyService = new FindingAssemblyService(new TestExplanationProvider(), suppressionStore);

        return new SingleRuleExplanationService(
            scannerCoordinator,
            ruleEvaluationService,
            findingAssemblyService,
            new AgentResultComposer(),
            state,
            machineRole);
    }

    private static Finding CreateFinding(string ruleId, string target)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = "Previous finding",
            Details = "Previous details",
            TimeRangeStart = now,
            TimeRangeEnd = now
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> EmptyHistory() =>
        new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistory(
        string ruleId,
        params Severity[] severities)
    {
        var now = DateTime.UtcNow;
        var snapshots = severities
            .Select((severity, index) => new RuleSeveritySnapshot
            {
                UtcTimestamp = now.AddDays(-(severities.Length - 1 - index)),
                Severity = severity
            })
            .ToArray();

        var previous = snapshots[^2].Severity;
        var current = snapshots[^1].Severity;
        var trend = current > previous
            ? RuleStatusTrend.Worsening
            : current < previous
                ? RuleStatusTrend.Improving
                : RuleStatusTrend.Stable;

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Test",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                Trend = trend,
                LastSeverity = current
            }
        };
    }

    private static IReadOnlyDictionary<string, RuleMemoryEntry> CreateHistoryWithCycles(
        string ruleId,
        Severity severity,
        int closedCycleCount)
    {
        var now = DateTime.UtcNow;
        var cycles = Enumerable.Range(1, closedCycleCount)
            .Select(i => new RemediationCycle
            {
                CycleNumber = i,
                AttemptedUtc = now.AddDays(-30 * (closedCycleCount - i + 1)),
                VerifiedFixedUtc = now.AddDays(-25 * (closedCycleCount - i + 1)),
                ReturnedUtc = now.AddDays(-10 * (closedCycleCount - i + 1))
            })
            .ToArray();

        var snapshots = new[]
        {
            new RuleSeveritySnapshot { UtcTimestamp = now.AddDays(-10), Severity = severity },
            new RuleSeveritySnapshot { UtcTimestamp = now, Severity = severity }
        };

        return new Dictionary<string, RuleMemoryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            [ruleId] = new RuleMemoryEntry
            {
                RuleId = ruleId,
                Category = "Firewall",
                FirstSeenUtc = snapshots[0].UtcTimestamp,
                LastSeenUtc = snapshots[^1].UtcTimestamp,
                SeverityHistory = snapshots,
                RemediationCycles = cycles,
                Trend = RuleStatusTrend.Stable,
                LastSeverity = severity
            }
        };
    }

    private sealed class NoopScanner : IScanner
    {
        public string Name => "Noop";

        public Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FailingRule : IRule
    {
        public string Id => "TEST-001";
        public string Category => "Test";
        public string Description => "Test failed";
        public string WhatItChecks => "Test";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity, "test-target");
        }
    }

    private sealed class PassingRule : IRule
    {
        public string Id => "TEST-002";
        public string Category => "Test";
        public string Description => "Test passed";
        public string WhatItChecks => "Test";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.Info;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Pass(Id, Category, Id, Description);
        }
    }

    private sealed class FwRule : IRule
    {
        public string Id => "FW-001";
        public string Category => "Firewall";
        public string Description => "Firewall rule failed";
        public string WhatItChecks => "Firewall";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.High;
        public IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

        public RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, Severity, "0.0.0.0/0");
        }
    }

    private sealed class TestExplanationProvider : IExplanationProvider
    {
        public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return $"explanation:{key}";
        }

        public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
        {
            return new StructuredExplanation { WhatWasFound = GetExplanation(key, variables) };
        }

        public StructuredExplanation ParseStructuredFromText(string text)
        {
            return new StructuredExplanation { WhatWasFound = text };
        }
    }
}
