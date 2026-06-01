using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RuleEvaluationServiceTests
{
    [Fact]
    public void EvaluateForIntent_FiltersRulesByCategory()
    {
        var service = new RuleEvaluationService(
            new IRule[]
            {
                new TestRule("FW-TEST", "Firewall"),
                new TestRule("SSH-TEST", "SSH")
            },
            MachineRole.Server,
            policyProvider: null);

        var result = service.EvaluateForIntent(AgentIntent.FirewallCheck, EmptyScanData(), CancellationToken.None);

        Assert.Single(result.RuleResults);
        Assert.Equal("FW-TEST", result.RuleResults[0].RuleId);
    }

    [Fact]
    public void EvaluateRule_DisabledPolicy_ReturnsDisabledPassResult()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { Enabled = false });
        var service = new RuleEvaluationService(new[] { new TestRule("TEST-001", "Test") }, MachineRole.Server, policyStore);

        var result = service.EvaluateRule(new TestRule("TEST-001", "Test"), EmptyScanData(), CancellationToken.None);

        Assert.True(result.DisabledByPolicy);
        Assert.True(result.RuleResult.Passed);
        Assert.Contains("disabled by policy", result.RuleResult.Description);
    }

    [Fact]
    public void EvaluateRule_ContextualRule_ReceivesRoleAndPolicy()
    {
        var policy = new RulePolicy { AutoPass = true };
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("CTX-001", MachineRole.Workstation, policy);
        var rule = new ContextualTestRule();
        var service = new RuleEvaluationService(new[] { rule }, MachineRole.Workstation, policyStore);

        service.EvaluateRule(rule, EmptyScanData(), CancellationToken.None);

        Assert.Equal(MachineRole.Workstation, rule.LastContext?.Role);
        Assert.Same(policy, rule.LastContext?.Policy);
    }

    [Fact]
    public void EvaluateRule_CrashedRule_ReturnsCrashResultAndWarning()
    {
        var rule = new ThrowingRule();
        var service = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyProvider: null);

        var result = service.EvaluateRule(rule, EmptyScanData(), CancellationToken.None);

        Assert.Equal(RuleStatus.Crashed, result.RuleResult.Status);
        Assert.Contains(result.Warnings, w => w.Contains("Rule CRASH-001 crashed: InvalidOperationException", StringComparison.Ordinal));
    }

    [Fact]
    public void EvaluateRule_AutoPass_ConvertsFailureToPass()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { AutoPass = true });
        var rule = new FailingRule("TEST-001", Severity.High);
        var service = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyStore);

        var result = service.EvaluateRule(rule, EmptyScanData(), CancellationToken.None);

        Assert.True(result.RuleResult.Passed);
        Assert.Equal(RuleStatus.Passed, result.RuleResult.Status);
    }

    [Fact]
    public void EvaluateRule_SeverityOverride_UpdatesFailureSeverity()
    {
        var policyStore = new InMemoryRulePolicyStore();
        policyStore.SetPolicy("TEST-001", MachineRole.Server, new RulePolicy { SeverityOverride = Severity.Critical });
        var rule = new FailingRule("TEST-001", Severity.Low);
        var service = new RuleEvaluationService(new[] { rule }, MachineRole.Server, policyStore);

        var result = service.EvaluateRule(rule, EmptyScanData(), CancellationToken.None);

        Assert.False(result.RuleResult.Passed);
        Assert.Equal(Severity.Critical, result.RuleResult.Severity);
    }

    private static ScanData EmptyScanData() => new ScanDataBuilder().Build();

    private class TestRule(string id, string category) : IRule
    {
        public string Id => id;
        public string Category => category;
        public string Description => "Test rule";
        public string WhatItChecks => "Test";
        public IReadOnlyList<string> SupportedDataSources => Array.Empty<string>();
        public Severity Severity => Severity.Low;

        public virtual RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Pass(Id, Category, Id, Description);
        }
    }

    private sealed class FailingRule(string id, Severity severity) : TestRule(id, "Test")
    {
        public override RuleResult Evaluate(ScanData data)
        {
            return RuleResult.Fail(Id, Category, Id, Description, severity, "target");
        }
    }

    private sealed class ThrowingRule : TestRule
    {
        public ThrowingRule()
            : base("CRASH-001", "Test")
        {
        }

        public override RuleResult Evaluate(ScanData data)
        {
            throw new InvalidOperationException("boom");
        }
    }

    private sealed class ContextualTestRule : TestRule, IContextualRule
    {
        public ContextualTestRule()
            : base("CTX-001", "Test")
        {
        }

        public RuleEvaluationContext? LastContext { get; private set; }

        public RuleResult Evaluate(ScanData data, RuleEvaluationContext context)
        {
            LastContext = context;
            return RuleResult.Fail(Id, Category, Id, Description, Severity.Low, "target");
        }
    }
}
