using System.Collections.Immutable;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class DefaultRulePolicyProviderTests
{
    [Fact]
    public void GetPolicy_Port001Server_IsStricter()
    {
        var provider = new DefaultRulePolicyProvider();
        var policy = provider.GetPolicy("PORT-001", MachineRole.Server);
        Assert.NotNull(policy);
        Assert.Equal("Fail", policy.Parameters["treatDefaultAs"]);
    }

    [Fact]
    public void GetPolicy_Port001Workstation_IsLooser()
    {
        var provider = new DefaultRulePolicyProvider();
        var policy = provider.GetPolicy("PORT-001", MachineRole.Workstation);
        Assert.NotNull(policy);
        Assert.Equal("Pass", policy.Parameters["treatDefaultAs"]);
    }

    [Fact]
    public void GetPolicy_Port002DevMachine_AddsDevPorts()
    {
        var provider = new DefaultRulePolicyProvider();
        var policy = provider.GetPolicy("PORT-002", MachineRole.DevMachine);
        Assert.NotNull(policy);
        Assert.Equal("22,80,443,8080,8443", policy.Parameters["expectedPublicPorts"]);
    }

    [Fact]
    public void GetPolicy_Srv005DevMachine_IgnoresNfsAndSmb()
    {
        var provider = new DefaultRulePolicyProvider();
        var policy = provider.GetPolicy("SRV-005", MachineRole.DevMachine);
        Assert.NotNull(policy);
        Assert.Equal("nfs,smb", policy.Parameters["ignoredServices"]);
    }

    [Fact]
    public void GetPolicy_UnknownRule_ReturnsNull()
    {
        var provider = new DefaultRulePolicyProvider();
        var policy = provider.GetPolicy("UNKNOWN-999", MachineRole.Server);
        Assert.Null(policy);
    }

    [Fact]
    public void GetPolicy_FallsBackToInnerProvider()
    {
        var inner = new InMemoryRulePolicyStore();
        inner.SetPolicy("CUSTOM-001", MachineRole.LabBox, new RulePolicy { AutoPass = true });
        var provider = new DefaultRulePolicyProvider(inner);

        var policy = provider.GetPolicy("CUSTOM-001", MachineRole.LabBox);
        Assert.NotNull(policy);
        Assert.True(policy.AutoPass);
    }

    [Fact]
    public void GetPolicy_UserOverrideWinsOverBuiltInPolicy()
    {
        var inner = new InMemoryRulePolicyStore();
        inner.SetPolicy("PORT-001", MachineRole.Workstation, new RulePolicy
        {
            Parameters = new Dictionary<string, string> { ["treatDefaultAs"] = "Fail" }.ToImmutableDictionary()
        });
        var provider = new DefaultRulePolicyProvider(inner);

        var policy = provider.GetPolicy("PORT-001", MachineRole.Workstation);

        Assert.NotNull(policy);
        Assert.Equal("Fail", policy.Parameters["treatDefaultAs"]);
    }

    [Fact]
    public void GetPolicy_UserOverrideMergesWithBuiltInParameters()
    {
        var inner = new InMemoryRulePolicyStore();
        inner.SetPolicy("PORT-002", MachineRole.DevMachine, new RulePolicy
        {
            SeverityOverride = Severity.High
        });
        var provider = new DefaultRulePolicyProvider(inner);

        var policy = provider.GetPolicy("PORT-002", MachineRole.DevMachine);

        Assert.NotNull(policy);
        Assert.Equal(Severity.High, policy.SeverityOverride);
        Assert.Equal("22,80,443,8080,8443", policy.Parameters["expectedPublicPorts"]);
    }
}
