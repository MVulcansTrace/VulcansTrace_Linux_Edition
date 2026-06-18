using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class FindingExplanationServiceTests
{
    [Fact]
    public async Task ExplainFindingAsync_BuildsStructuredSummaryFromFindingDetails()
    {
        var service = CreateService(new FailingRule());
        var finding = CreateFinding("FW-001", "0.0.0.0/0", Severity.High);

        var result = await service.ExplainFindingAsync(finding, CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Same(finding, Assert.Single(result.AgentFindings));
        Assert.Contains("[FW-001] FW-001 finding", result.Summary);
        Assert.Contains("What was found", result.Summary);
        Assert.Contains("parsed-found:Details for FW-001", result.Summary);
        Assert.Contains("Why it matters", result.Summary);
        Assert.Contains("parsed-why:Details for FW-001", result.Summary);
        Assert.Contains("How to verify", result.Summary);
        Assert.Contains("Suggested next action", result.Summary);
        Assert.Contains("Confidence:", result.Summary);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_TargetReferenceMatchesPreviousFindingAndPreservesAuditState()
    {
        var state = new AgentAuditState();
        var previousFinding = CreateFinding("SSH-001", "sshd_config", Severity.High) with
        {
            Category = "SSH",
            ShortDescription = "Weak SSH configuration"
        };
        var previousResult = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            AgentFindings = new[] { previousFinding }
        };
        state.RememberAudit(previousResult, AgentIntent.SshCheck, new[] { ("SSH-001", previousFinding) });
        var service = CreateService(new FailingRule(), state);

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "weak ssh"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Same(previousFinding, Assert.Single(result.AgentFindings));
        Assert.Contains("Weak SSH configuration", result.Summary);
        Assert.Same(previousResult, state.LastResult);
        Assert.Equal(AgentIntent.SshCheck, state.LastAuditIntent);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_TargetReferenceMatchesRuleIdRunsSingleRuleExplanation()
    {
        var state = new AgentAuditState();
        var rule = new FailingRule();
        var service = CreateService(rule, state);

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "TEST-001"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Single(result.AgentFindings);
        Assert.Equal("TEST-001", result.AgentFindings[0].RuleId);
        Assert.Equal(1, result.FailedCount);
        Assert.Contains("Explanation for [High] Test failed", result.Summary);
        Assert.Null(state.LastResult);
        Assert.Null(state.FindPreviousFinding("TEST-001"));
    }

    [Fact]
    public async Task HandleExplainFindingAsync_UnknownReferenceReturnsGuidance()
    {
        var service = CreateService(new FailingRule());

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding, "NOPE-404"), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("I don't have a finding matching 'NOPE-404'", result.Summary);
    }

    [Fact]
    public async Task HandleExplainFindingAsync_MissingReferenceReturnsSelectionGuidance()
    {
        var service = CreateService(new FailingRule());

        var result = await service.HandleExplainFindingAsync(new AgentQuery(AgentIntent.ExplainFinding), CancellationToken.None);

        Assert.Equal(AgentIntent.ExplainFinding, result.Intent);
        Assert.Empty(result.AgentFindings);
        Assert.Contains("Please specify a finding", result.Summary);
        Assert.Contains("select one from the findings list", result.Summary);
    }

    private static FindingExplanationService CreateService(IRule rule, AgentAuditState? state = null)
    {
        state ??= new AgentAuditState();
        var explanationProvider = new TestExplanationProvider();
        var scannerCoordinator = new ScannerCoordinator(new[] { new NoopScanner() });
        var ruleEvaluationService = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyProvider: null);
        var findingAssemblyService = new FindingAssemblyService(explanationProvider, suppressionStore: null);
        var singleRuleExplanationService = new SingleRuleExplanationService(
            scannerCoordinator,
            ruleEvaluationService,
            findingAssemblyService,
            new AgentResultComposer(),
            state,
            MachineRole.Server);

        return new FindingExplanationService(
            state,
            ruleEvaluationService,
            explanationProvider,
            singleRuleExplanationService);
    }

    private static Finding CreateFinding(string ruleId, string target, Severity severity)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            RuleId = ruleId,
            Category = "Test",
            Severity = severity,
            SourceHost = "localhost",
            Target = target,
            ShortDescription = $"{ruleId} finding",
            Details = $"Details for {ruleId}",
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
            return new StructuredExplanation
            {
                WhatWasFound = $"parsed-found:{text}",
                WhyItMatters = $"parsed-why:{text}",
                HowToVerify = "parsed-verify",
                SuggestedNextAction = "parsed-action",
                Confidence = "High",
                Caveats = "parsed-caveat"
            };
        }
    }
}
