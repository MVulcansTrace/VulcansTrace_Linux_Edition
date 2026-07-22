using System;
using VulcansTrace.Linux.Avalonia.Services;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class MachineModeTests : IDisposable
{
    public MachineModeTests()
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", null);
        Environment.SetEnvironmentVariable("VT_REDUCED_MOTION", null);
        MachineMode.ResetForTests();
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", null);
        Environment.SetEnvironmentVariable("VT_REDUCED_MOTION", null);
        MachineMode.ResetForTests();
    }

    [Theory]
    [InlineData("1")]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("Yes")]
    public void IsEnabled_TruthyValues_EnableMachineMode(string value)
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", value);
        MachineMode.ResetForTests();

        Assert.True(MachineMode.IsEnabled);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("false")]
    [InlineData("")]
    [InlineData("enabled")]
    public void IsEnabled_NonTruthyValues_LeaveMachineModeOff(string value)
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", value);
        MachineMode.ResetForTests();

        Assert.False(MachineMode.IsEnabled);
    }

    [Fact]
    public void IsEnabled_Unset_LeavesMachineModeOff()
    {
        Assert.False(MachineMode.IsEnabled);
    }

    [Fact]
    public void IsEnabled_CachesFirstRead_UntilReset()
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", "1");
        MachineMode.ResetForTests();
        Assert.True(MachineMode.IsEnabled);

        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", null);
        Assert.True(MachineMode.IsEnabled); // cached read wins

        MachineMode.ResetForTests();
        Assert.False(MachineMode.IsEnabled);
    }

    [Fact]
    public void MotionSettings_ReducedMotionOptOut_DisablesOptionalMotion()
    {
        Environment.SetEnvironmentVariable("VT_REDUCED_MOTION", "true");

        Assert.False(MotionSettings.IsEnabled);
    }

    [Fact]
    public void MotionSettings_MachineMode_DisablesOptionalMotion()
    {
        Environment.SetEnvironmentVariable("VT_MACHINE_MODE", "1");
        MachineMode.ResetForTests();

        Assert.False(MotionSettings.IsEnabled);
    }
}
