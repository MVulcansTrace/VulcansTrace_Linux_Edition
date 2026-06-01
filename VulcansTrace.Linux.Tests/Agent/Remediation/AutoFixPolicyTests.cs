using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class AutoFixPolicyTests
{
    [Theory]
    [InlineData(CommandSafety.ReadOnly, true, true, true)]
    [InlineData(CommandSafety.ConfigChange, false, true, true)]
    [InlineData(CommandSafety.ServiceRestart, false, false, true)]
    [InlineData(CommandSafety.PackageInstall, false, false, false)]
    [InlineData(CommandSafety.Destructive, false, false, false)]
    [InlineData(CommandSafety.Unknown, false, false, false)]
    public void ConservativePolicy_OnlyAllowsReadOnly(
        CommandSafety safety, bool expectedConservative, bool expectedStandard, bool expectedAggressive)
    {
        Assert.Equal(expectedConservative, AutoFixPolicy.Conservative().IsPermitted(safety));
        Assert.Equal(expectedStandard, AutoFixPolicy.Standard().IsPermitted(safety));
        Assert.Equal(expectedAggressive, AutoFixPolicy.Aggressive().IsPermitted(safety));
    }

    [Fact]
    public void StandardPolicy_BlocksServiceRestartAndPackages()
    {
        var policy = AutoFixPolicy.Standard();

        Assert.True(policy.IsPermitted(CommandSafety.ReadOnly));
        Assert.True(policy.IsPermitted(CommandSafety.ConfigChange));
        Assert.False(policy.IsPermitted(CommandSafety.ServiceRestart));
        Assert.False(policy.IsPermitted(CommandSafety.PackageInstall));
        Assert.False(policy.IsPermitted(CommandSafety.Destructive));
        Assert.False(policy.IsPermitted(CommandSafety.Unknown));
    }

    [Fact]
    public void AggressivePolicy_AllowsConfigAndService()
    {
        var policy = AutoFixPolicy.Aggressive();

        Assert.True(policy.IsPermitted(CommandSafety.ReadOnly));
        Assert.True(policy.IsPermitted(CommandSafety.ConfigChange));
        Assert.True(policy.IsPermitted(CommandSafety.ServiceRestart));
        Assert.False(policy.IsPermitted(CommandSafety.PackageInstall));
        Assert.False(policy.IsPermitted(CommandSafety.Destructive));
        Assert.False(policy.IsPermitted(CommandSafety.Unknown));
    }

    [Fact]
    public void CustomPolicy_WithPackages_AllowsPackages()
    {
        var policy = AutoFixPolicy.Standard() with { AllowPackageInstall = true };

        Assert.True(policy.IsPermitted(CommandSafety.PackageInstall));
        Assert.False(policy.IsPermitted(CommandSafety.Destructive));
    }

    [Fact]
    public void Describe_Conservative_ReturnsReadOnlyOnly()
    {
        var description = AutoFixPolicy.Conservative().Describe();
        Assert.Equal("allows: read-only verification", description);
    }

    [Fact]
    public void Describe_Standard_ReturnsExpected()
    {
        var description = AutoFixPolicy.Standard().Describe();
        Assert.Contains("read-only verification", description);
        Assert.Contains("config changes", description);
    }

    [Fact]
    public void Describe_Aggressive_ReturnsExpected()
    {
        var description = AutoFixPolicy.Aggressive().Describe();
        Assert.Contains("read-only verification", description);
        Assert.Contains("config changes", description);
        Assert.Contains("service restarts", description);
    }

    [Fact]
    public void Default_ValidationAndRollbackEnabled()
    {
        var policy = new AutoFixPolicy();
        Assert.True(policy.RequireValidation);
        Assert.True(policy.RequireRollbackGuidance);
    }
}
