using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
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
    public async Task ExplainAsync_FailingRule_ReturnsFindingAndUpdatesState()
    {
        var state = new AgentAuditState();
        var service = CreateService(new FailingRule(), state: state);

        var result = await service.ExplainAsync(new FailingRule(), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("Explanation for [High] Test failed\n\nexplanation:TEST-001", result.Summary);
        Assert.Equal(1, result.FailedCount);
        Assert.Same(result, state.LastResult);
        Assert.Same(result.AgentFindings[0], state.FindPreviousFinding("TEST-001"));
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

        var result = await service.ExplainAsync(rule, CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Contains("Rule TEST-001 is disabled by policy for Workstation.", result.Summary);
        Assert.Equal(1, result.PassedCount);
        Assert.Same(previous, state.LastResult);
        Assert.Null(state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public async Task ExplainAsync_SuppressedFailure_StillReturnsFinding()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry { RuleId = "TEST-001", Target = "test-target" });
        var rule = new FailingRule();
        var service = CreateService(rule, suppressionStore: suppressionStore);

        var result = await service.ExplainAsync(rule, CancellationToken.None);

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

        var result = await service.ExplainAsync(rule, CancellationToken.None);

        Assert.Empty(result.AgentFindings);
        Assert.Equal("Rule TEST-002 passed — no issue to explain.", result.Summary);
        Assert.Equal(1, result.PassedCount);
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
