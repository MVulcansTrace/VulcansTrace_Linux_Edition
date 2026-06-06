using VulcansTrace.Linux.Engine.Live;
using VulcansTrace.Linux.Engine.Net;

namespace VulcansTrace.Linux.Tests.Engine.Live;

public class DemoPatternsTests
{
    [Theory]
    [InlineData(DemoScenario.C2Beaconing)]
    [InlineData(DemoScenario.SshBruteforce)]
    [InlineData(DemoScenario.PrivilegeEscalation)]
    [InlineData(DemoScenario.RandomMix)]
    public void For_EachScenario_ReturnsNonNull(DemoScenario scenario)
    {
        var patterns = DemoPatterns.For(scenario);
        Assert.NotNull(patterns);
    }

    [Fact]
    public void C2Beaconing_HasBeaconingEnabled()
    {
        var patterns = DemoPatterns.For(DemoScenario.C2Beaconing);
        Assert.True(patterns.BeaconingEnabled);
        Assert.False(patterns.PortScanEnabled);
        Assert.False(patterns.FloodEnabled);
        Assert.False(patterns.AdminPortSweepEnabled);
        Assert.False(patterns.TargetedFloodEnabled);
        Assert.False(patterns.BackgroundTrafficEnabled);
        Assert.True(IpClassification.IsExternal(patterns.BeaconDestinationIp));
        Assert.Equal(0, patterns.BeaconInitialDelaySeconds);
        Assert.Equal(0, patterns.BeaconJitterSeconds);
    }

    [Fact]
    public void C2Beaconing_BeaconInterval_IsWithinHighDetectorTolerance()
    {
        var patterns = DemoPatterns.For(DemoScenario.C2Beaconing);
        // High intensity: C2MinIntervalSeconds = 30, C2ToleranceSeconds = 8
        // Beacon interval must be >= 30 to pass C2MinIntervalSeconds filter.
        Assert.True(patterns.BeaconIntervalSeconds >= 30.0,
            $"Beacon interval {patterns.BeaconIntervalSeconds}s must be >= 30s for C2 detection at High intensity.");
    }

    [Fact]
    public void SshBruteforce_HasTargetedFloodEnabled()
    {
        var patterns = DemoPatterns.For(DemoScenario.SshBruteforce);
        Assert.True(patterns.TargetedFloodEnabled);
        Assert.Equal(22, patterns.TargetedFloodPort);
        Assert.False(patterns.PortScanEnabled);
        Assert.False(patterns.BeaconingEnabled);
        Assert.False(patterns.AdminPortSweepEnabled);
        Assert.False(patterns.BackgroundTrafficEnabled);
        Assert.NotNull(patterns.FixedAttackSourceIp);
        Assert.NotNull(patterns.FixedTargetIp);
    }

    [Fact]
    public void PrivilegeEscalation_HasAdminPortSweepEnabled()
    {
        var patterns = DemoPatterns.For(DemoScenario.PrivilegeEscalation);
        Assert.True(patterns.AdminPortSweepEnabled);
        Assert.NotEmpty(patterns.AdminPorts);
        Assert.False(patterns.PortScanEnabled);
        Assert.False(patterns.BeaconingEnabled);
        Assert.False(patterns.TargetedFloodEnabled);
        Assert.False(patterns.BackgroundTrafficEnabled);
        Assert.NotNull(patterns.FixedAttackSourceIp);
        Assert.NotNull(patterns.FixedTargetIp);
        Assert.Equal(4, patterns.AdminPortSweepMinEventsPerBurst);
        Assert.Equal(4, patterns.AdminPortSweepMaxEventsPerBurst);
        Assert.True(patterns.EventDelayMs >= 3000);
    }

    [Fact]
    public void RandomMix_HasDefaults()
    {
        var patterns = DemoPatterns.For(DemoScenario.RandomMix);
        Assert.True(patterns.PortScanEnabled);
        Assert.True(patterns.BeaconingEnabled);
        Assert.True(patterns.FloodEnabled);
        Assert.True(patterns.BackgroundTrafficEnabled);
        Assert.False(patterns.AdminPortSweepEnabled);
        Assert.False(patterns.TargetedFloodEnabled);
    }

    [Fact]
    public void RandomMix_IsIdenticalToDefaultSyntheticPatterns()
    {
        var demoPatterns = DemoPatterns.For(DemoScenario.RandomMix);
        var defaultPatterns = new SyntheticPatterns();

        Assert.Equal(defaultPatterns.PortScanEnabled, demoPatterns.PortScanEnabled);
        Assert.Equal(defaultPatterns.BeaconingEnabled, demoPatterns.BeaconingEnabled);
        Assert.Equal(defaultPatterns.FloodEnabled, demoPatterns.FloodEnabled);
        Assert.Equal(defaultPatterns.EventDelayMs, demoPatterns.EventDelayMs);
        Assert.Equal(defaultPatterns.BeaconIntervalSeconds, demoPatterns.BeaconIntervalSeconds);
        Assert.Equal(defaultPatterns.BeaconInitialDelaySeconds, demoPatterns.BeaconInitialDelaySeconds);
        Assert.Equal(defaultPatterns.BeaconJitterSeconds, demoPatterns.BeaconJitterSeconds);
        Assert.Equal(defaultPatterns.BackgroundTrafficEnabled, demoPatterns.BackgroundTrafficEnabled);
    }
}
